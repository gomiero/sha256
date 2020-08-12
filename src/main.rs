// MIT License
// 
// Copyright (c) 2018 Alexandre Gomiero de Oliveira
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


// Converte um array de 4 bytes em u32 Big Endian
#[inline]
fn conv(x: &[u8]) -> Option<u32> {
    let ret: u32 = unsafe { std::mem::transmute::<[u8; 4], u32>([
        x[3],
        x[2],
        x[1],
        x[0]
    ]) };
    Some(ret)
}

// Calcula o hash SHA256
// Parâmetro: [b] str String estática
// Retorno: String hexadecimal contendo o hash
pub fn sha256(b: &str) -> String {
    // Inicialização das variáveis
    // Primeiros 32 bits da parte fracional da raiz quadrada dos 8 primeiros números primos
    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;
    let mut h4: u32 = 0x510e527f;
    let mut h5: u32 = 0x9b05688c;
    let mut h6: u32 = 0x1f83d9ab;
    let mut h7: u32 = 0x5be0cd19;
    
    // Array de constantes
    // Primeiros 32 bits da parte fracional da raiz cúbica dos 64 primeiros números primos
    let k: Vec<u32> =
        vec![0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    
    // Converte a str em um array de bytes, em seguida, em um Vec<u8>
    let mut vb: Vec<u8> = b.as_bytes().to_vec();
    // Armazena o comprimento do array
    let vlen = vb.len() as u64;

    // ==> Início do algoritmo <==
    // Acrescenta 1 bit (0x80) na mensagem
    vb.push(0x80);
    // Calcula o tamanho do pad (56 - o tamanho mais o byte 0x80 % 64 (= 512 bits)
    let padsize: usize = (56 - (vlen+1) % 64) as usize;
    // Cria o vetor pad
    let mut num: Vec<u8> = vec![0u8; padsize];
    // Acrescenta o pad na string
    vb.append(&mut num);
    // Converte o tamanho da str em bits (comprimento * 8) e transforma em um vetor u8
    let tamanho: [u8; 8] = unsafe { std::mem::transmute::<u64, [u8; 8]>((vlen*8).to_be()) };
    // Acrescenta o tamanho na string
    vb.append(&mut tamanho.to_vec());  
    
     // Divide a mensagem em chunks de 64 bytes (512 bits)
    for ck in vb.chunks(64) {
        // Cria um array de 64 entradas de palavras de 32-bit
        // Os valores iniciais não importam
        let mut w: Vec<u32> = Vec::with_capacity(64);
        // Copia as primeiras 16 palavras do chunk nas primeiras posições do array
        for _i in 0..16 {
            let vv = conv(&ck[_i*4.._i*4+4]).unwrap();
            w.push(vv);
        } 
        // Extende as 16 palavras copiadas para as demais 48
        // Cuidado!: as 2 primeiras operações são rotate, mas a última é SHIFT!!!!
        for _i in 16..64 {
            let s0: u32 = w[_i-15].rotate_right(7) ^ w[_i-15].rotate_right(18) ^ w[_i-15] >> 3;
            let s1: u32 = w[_i-2].rotate_right(17) ^ w[_i-2].rotate_right(19) ^ w[_i-2] >> 10;
            let elem: u32 = w[_i-16] + s0 + w[_i-7] + s1;
            w.push(elem);
        }

        // Inicializa as variáveis de trabalho para os valores atuais do hash
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;
        // Função de compressão. Looping princial
        for _i in 0..64 {
            let s1: u32 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch: u32 = (e & f) ^ ((!e) & g);
            let temp1: u32 = h + s1 + ch + k[_i] + w[_i];
            let s0: u32 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj: u32 = (a & b) ^ (a & c) ^ (b & c);
            let temp2: u32 = s0 + maj;
            // Atualiza as variáveis de trabalho
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        // Adiciona o chunk já comprimido ao hash
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    // Retorna a string com o hash SHA256 (não precisa transformar em Big Endian)
    String::from(format!("{:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}",
                         h0,
                         h1,
                         h2,
                         h3,
                         h4,
                         h5,
                         h6,
                         h7))
}

// Função de entrada
fn main() {
    // Testes - string vazia, deve retornar => e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let s = "";
    println!("SHA256(\"{}\") ==>\n{}", s, sha256(s));
    println!("\n");
    let s = "The quick brown fox jumps over the lazy dog";
    println!("SHA256(\"{}\") ==>\n{}", s, sha256(s));
}
