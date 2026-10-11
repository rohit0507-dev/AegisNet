"use strict";

// These calculations use the values entered in CN tools, not live packets.
// They return results only; app.js handles inputs and displays the output.

function crcRemainder(bits, generator) {
  const dividend = [...bits].map(Number);
  const divisor = [...generator].map(Number);

  // XOR performs subtraction in modulo-2 polynomial division.
  for (let start = 0; start <= dividend.length - divisor.length; start++) {
    if (dividend[start] === 1) {
      for (let offset = 0; offset < divisor.length; offset++) {
        dividend[start + offset] ^= divisor[offset];
      }
    }
  }
  return dividend.slice(-(divisor.length - 1)).join("");
}

function internetChecksum(text) {
  const data = new TextEncoder().encode(text);
  let sum = 0;

  // Read 16-bit words in network byte order. Pad an odd last byte with zero.
  for (let index = 0; index < data.length; index += 2) {
    const highByte = data[index];
    const lowByte = data[index + 1] || 0;
    sum += (highByte << 8) + lowByte;
  }
  while (sum >>> 16) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  return ~sum & 0xffff;
}

function hamming(bits) {
  // Array indices are zero-based; Hamming positions are numbered 1 to 7.
  // Positions 1, 2, and 4 are parity bits. Data occupies 3, 5, 6, and 7.
  const codeword = [
    0,
    0,
    Number(bits[0]),
    0,
    Number(bits[1]),
    Number(bits[2]),
    Number(bits[3]),
  ];

  for (const parityPosition of [1, 2, 4]) {
    let parity = 0;
    for (let position = 1; position <= 7; position++) {
      if (position & parityPosition && position !== parityPosition) {
        parity ^= codeword[position - 1];
      }
    }
    codeword[parityPosition - 1] = parity;
  }
  return codeword;
}
