#include <sys/types.h>
#include <vector>
#include <string>
#define uint unsigned int
size_t nums[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
uint RotR(uint A,uint n) {
    return (A>>n)|(A<<(32-n));
}
uint ShR(uint A,uint n) {
    return A>>n;
}
size_t Concat(unsigned int A, unsigned int B) {
    return ((size_t)A << 32) | B;
}
uint Ch(uint A,uint B,uint C) {
    return (A&B)^((~A)&C);
}
uint Maj(uint A,uint B,uint C) {
    return (A&B)^(A&C)^(B&C);
}
uint sig0(uint x) {
    return RotR(x,2)^RotR(x,13)^RotR(x,22);
}
uint sig1(uint x) {
    return RotR(x,6)^RotR(x,11)^RotR(x,25);
}
uint ssig0(uint x) {
    return RotR(x,7)^RotR(x,18)^ShR(x,3);
}
uint ssig1(uint x) {
    return RotR(x,17)^RotR(x,19)^ShR(x,10);
}
class bits {
public:
    std::vector<uint> v=std::vector(1,(uint)0);
    size_t len=0;
    bool at(size_t i) {
        if (i<len) {
            return (v[i/(size_t)32]>>((size_t)31-i%((size_t)32)))&1;
        } else return 0;
    }
    void push_back(bool x) {
        if (len/(size_t)32==v.size()) {
            v.push_back(0);
        }
        v[len/(size_t)32]+=x<<((size_t)31-len%((size_t)32));
        len++;
    }
    void push_char_back(unsigned char c) {
        for (int i=0;i<8;i++) {
            push_back((c>>(7-i))&1);
        }
    }
    void push_size_t_back(size_t st) {
        for (int i=0;i<64;i++) {
            push_back((st>>(63-i))&1);
        }
    }
    void push_str_back(std::string s) {
        for (int i=0;i<s.size();i++) {
            push_char_back(s[i]);
        }
    }
    size_t size() {
        return len;
    }
};
class SHA256 {
    bits b;
    std::vector<uint> v;
    SHA256(std::string s) {
        //message
        b=bits();
        b.push_str_back(s);
        size_t l=b.len;
        //padding
        b.push_back(true);
        while ((b.len)%(size_t)512!=(size_t)448) {
            b.push_back(false);
        }
        b.push_size_t_back(l);
        //block decomp
        size_t size=b.v.size();
        size_t i=0;
        while (i<size) {
            for (int j=0;j<16;j++) {
                v.push_back(b.v[i++]);
            }
            for (int j=16;j<64;j++) {
                v.push_back(sig1(v[j-2])+v[j-7]+sig0(v[j-15])+v[j-16]);
            }
        }
    }
};
