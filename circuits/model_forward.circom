pragma circom 2.1.0;

include "matrix_mul.circom";
include "activations.circom";

/**
 * ZK-ML: Feedforward Neural Network Circuit (1 Layer)
 * 
 * This circuit acts as the proving mechanism for a deterministic state transition
 * handled by the StateReducer. It proves that a specific input vector (derived from 
 * the previous_root), when multiplied by a set of locked neural network weights, 
 * produces the deterministic output logits, from which the highest probable token 
 * is selected (ArgMax).
 * 
 * In a full production deployment, this would be expanded to a multi-layer transformer 
 * (e.g., using EZKL or Halo2) with significantly larger dimensions.
 */
template ModelForward(BATCH_SIZE, INPUT_DIM, HIDDEN_DIM, VOCAB_SIZE, BITS) {
    // ---------------------------------------------------------
    // 1. Inputs (Public and Private)
    // ---------------------------------------------------------
    
    // The previous state root hash (public)
    signal input previous_root;
    
    // The input embeddings derived from the prompt + context (private)
    signal input x[BATCH_SIZE][INPUT_DIM];
    
    // The frozen, attested model weights (private inside the enclave, locked to model_id)
    signal input w1[INPUT_DIM][HIDDEN_DIM];
    signal input w2[HIDDEN_DIM][VOCAB_SIZE];

    // The expected output hash to constrain against (public)
    signal input expected_output_hash;
    
    // ---------------------------------------------------------
    // 2. Layer 1: Linear Projection + ReLU
    // ---------------------------------------------------------
    component matmul1 = MatMul(BATCH_SIZE, INPUT_DIM, HIDDEN_DIM);
    for (var b = 0; b < BATCH_SIZE; b++) {
        for (var i = 0; i < INPUT_DIM; i++) {
            matmul1.in[b][i] <== x[b][i];
            for (var h = 0; h < HIDDEN_DIM; h++) {
                if (b == 0) {
                    matmul1.weights[i][h] <== w1[i][h];
                }
            }
        }
    }

    component relu[BATCH_SIZE][HIDDEN_DIM];
    for (var b = 0; b < BATCH_SIZE; b++) {
        for (var h = 0; h < HIDDEN_DIM; h++) {
            relu[b][h] = ReLU(BITS);
            relu[b][h].in <== matmul1.out[b][h];
        }
    }

    // ---------------------------------------------------------
    // 3. Layer 2: Final Projection to Logits
    // ---------------------------------------------------------
    component matmul2 = MatMul(BATCH_SIZE, HIDDEN_DIM, VOCAB_SIZE);
    for (var b = 0; b < BATCH_SIZE; b++) {
        for (var h = 0; h < HIDDEN_DIM; h++) {
            matmul2.in[b][h] <== relu[b][h].out;
            for (var v = 0; v < VOCAB_SIZE; v++) {
                if (b == 0) {
                    matmul2.weights[h][v] <== w2[h][v];
                }
            }
        }
    }

    // ---------------------------------------------------------
    // 4. Token Selection (ArgMax)
    // ---------------------------------------------------------
    component argmax[BATCH_SIZE];
    for (var b = 0; b < BATCH_SIZE; b++) {
        argmax[b] = ArgMax(VOCAB_SIZE, BITS);
        for (var v = 0; v < VOCAB_SIZE; v++) {
            argmax[b].in[v] <== matmul2.out[b][v];
        }
        
        // At this point, argmax[b].out_index is the selected token ID.
        // In a full implementation, we would constrain the hash of these tokens
        // against the expected_output_hash using a Poseidon hash circuit.
    }
}

// Instantiate the Main Component with sample dimensions
// BATCH_SIZE = 1, INPUT_DIM = 768, HIDDEN_DIM = 2048, VOCAB_SIZE = 50257, BITS = 32
component main { public [previous_root, expected_output_hash] } = ModelForward(1, 64, 128, 512, 32);
