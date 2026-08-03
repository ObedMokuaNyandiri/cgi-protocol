pragma circom 2.1.0;

/**
 * ZK-ML: Matrix Multiplication Circuit
 * 
 * Computes the dot product of a batch of inputs and a weight matrix.
 * Represents the linear projection layer in a Transformer network: Y = X * W
 * 
 * Note: Assumes the inputs and weights are quantized integers. 
 * Floating point arithmetic is not natively supported in finite fields.
 */
template MatMul(BATCH_SIZE, INPUT_DIM, OUTPUT_DIM) {
    // Inputs
    signal input in[BATCH_SIZE][INPUT_DIM];
    signal input weights[INPUT_DIM][OUTPUT_DIM];

    // Output
    signal output out[BATCH_SIZE][OUTPUT_DIM];

    // Compute the matrix multiplication
    for (var b = 0; b < BATCH_SIZE; b++) {
        for (var o = 0; o < OUTPUT_DIM; o++) {
            var sum = 0;
            for (var i = 0; i < INPUT_DIM; i++) {
                sum += in[b][i] * weights[i][o];
            }
            // Constraint: the output signal must exactly equal the computed sum
            out[b][o] <== sum;
        }
    }
}
