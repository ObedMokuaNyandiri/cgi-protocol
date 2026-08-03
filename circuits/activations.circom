pragma circom 2.1.0;

/**
 * ZK-ML: Activation Functions and Output Selection
 * 
 * Provides cryptographic proofs for ReLU non-linearities and ArgMax (token selection).
 */

// Basic Num2Bits template to decompose a field element into binary
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1 = 0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 += out[i] * e2;
        e2 = e2 + e2;
    }

    lc1 === in;
}

// GreaterThan compares if in[0] > in[1]
template GreaterThan(n) {
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n + 1);
    // Add 2^n to in[0] to ensure the result is positive before subtraction
    n2b.in <== in[0] + (1 << n) - in[1];
    
    // If in[0] >= in[1], the highest bit (n-th bit) will be 1
    out <== n2b.out[n];
}

// RelU: out = in if in > 0 else 0
template ReLU(n) {
    signal input in;
    signal output out;

    component gt = GreaterThan(n);
    gt.in[0] <== in;
    gt.in[1] <== 0;

    // If gt.out == 1 (in > 0), out = in. Else out = 0.
    out <== in * gt.out;
}

// ArgMax: Finds the index of the maximum value in an array.
// Used as an efficient approximation for Softmax when we only need 
// to prove the selection of the most probable token.
template ArgMax(ARRAY_SIZE, BITS) {
    signal input in[ARRAY_SIZE];
    signal output out_index;
    signal output out_max;

    component gt[ARRAY_SIZE - 1];
    
    signal max_vals[ARRAY_SIZE];
    signal max_idxs[ARRAY_SIZE];

    max_vals[0] <== in[0];
    max_idxs[0] <== 0;

    for (var i = 1; i < ARRAY_SIZE; i++) {
        gt[i-1] = GreaterThan(BITS);
        gt[i-1].in[0] <== in[i];
        gt[i-1].in[1] <== max_vals[i-1];

        // Update max value
        max_vals[i] <== gt[i-1].out * (in[i] - max_vals[i-1]) + max_vals[i-1];
        
        // Update max index
        max_idxs[i] <== gt[i-1].out * (i - max_idxs[i-1]) + max_idxs[i-1];
    }

    out_max <== max_vals[ARRAY_SIZE - 1];
    out_index <== max_idxs[ARRAY_SIZE - 1];
}
