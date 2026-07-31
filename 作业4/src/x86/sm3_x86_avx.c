#include "sm3_internal.h"

#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(_M_X64))
#include <immintrin.h>
#include <string.h>

#define VROL256(x,n) _mm256_or_si256(_mm256_slli_epi32((x),(n)),_mm256_srli_epi32((x),32-(n)))
#define VX256(a,b,c) _mm256_xor_si256(_mm256_xor_si256((a),(b)),(c))

__attribute__((target("avx2")))
static void compress8(uint32_t st[8][8], const uint8_t *p[8])
{
    __m256i w[68], wp, a,b,c,d,e,f,g,h, old[8];
    uint32_t x[8]; int i,j;
    for (j=0;j<16;++j) {
        for(i=0;i<8;++i) x[i]=sm3_load_be32(p[i]+4*j);
        w[j]=_mm256_loadu_si256((const __m256i*)x);
    }
    for(j=16;j<68;++j) {
        __m256i q=VX256(w[j-16],w[j-9],VROL256(w[j-3],15));
        w[j]=VX256(VX256(q,VROL256(q,15),VROL256(q,23)),VROL256(w[j-13],7),w[j-6]);
    }
#define LOAD8(k) _mm256_setr_epi32(st[0][k],st[1][k],st[2][k],st[3][k],st[4][k],st[5][k],st[6][k],st[7][k])
    a=old[0]=LOAD8(0); b=old[1]=LOAD8(1); c=old[2]=LOAD8(2); d=old[3]=LOAD8(3);
    e=old[4]=LOAD8(4); f=old[5]=LOAD8(5); g=old[6]=LOAD8(6); h=old[7]=LOAD8(7);
    for(j=0;j<64;++j) {
        __m256i tj=_mm256_set1_epi32((int)sm3_rol32(j<16?0x79cc4519U:0x7a879d8aU,j));
        __m256i ar=VROL256(a,12);
        __m256i ss1=VROL256(_mm256_add_epi32(_mm256_add_epi32(ar,e),tj),7);
        __m256i ss2=_mm256_xor_si256(ss1,ar), ff,gg,tt1,tt2;
        if(j<16) { ff=VX256(a,b,c); gg=VX256(e,f,g); }
        else {
            ff=_mm256_or_si256(_mm256_or_si256(_mm256_and_si256(a,b),_mm256_and_si256(a,c)),_mm256_and_si256(b,c));
            gg=_mm256_or_si256(_mm256_and_si256(e,f),_mm256_andnot_si256(e,g));
        }
        wp=_mm256_xor_si256(w[j],w[j+4]);
        tt1=_mm256_add_epi32(_mm256_add_epi32(ff,d),_mm256_add_epi32(ss2,wp));
        tt2=_mm256_add_epi32(_mm256_add_epi32(gg,h),_mm256_add_epi32(ss1,w[j]));
        d=c;c=VROL256(b,9);b=a;a=tt1;h=g;g=VROL256(f,19);f=e;
        e=VX256(tt2,VROL256(tt2,9),VROL256(tt2,17));
    }
    old[0]=_mm256_xor_si256(old[0],a); old[1]=_mm256_xor_si256(old[1],b);
    old[2]=_mm256_xor_si256(old[2],c); old[3]=_mm256_xor_si256(old[3],d);
    old[4]=_mm256_xor_si256(old[4],e); old[5]=_mm256_xor_si256(old[5],f);
    old[6]=_mm256_xor_si256(old[6],g); old[7]=_mm256_xor_si256(old[7],h);
    for(j=0;j<8;++j) { _mm256_storeu_si256((__m256i*)x,old[j]); for(i=0;i<8;++i) st[i][j]=x[i]; }
#undef LOAD8
}

__attribute__((target("avx2")))
static void hash8(const uint8_t *const d[8], size_t len, uint8_t out[8][32])
{
    uint32_t st[8][8]; uint8_t tail[8][128]; const uint8_t *p[8];
    size_t full=len&~(size_t)63, rem=len-full, pad=rem<56?64:128, off,i,j;
    for(i=0;i<8;++i) memcpy(st[i],sm3_iv,32);
    for(off=0;off<full;off+=64) { for(i=0;i<8;++i)p[i]=d[i]+off; compress8(st,p); }
    for(i=0;i<8;++i) {
        memset(tail[i],0,pad); if(rem)memcpy(tail[i],d[i]+full,rem); tail[i][rem]=0x80;
        for(j=0;j<8;++j) tail[i][pad-1-j]=(uint8_t)(((uint64_t)len*8)>>(8*j));
        p[i]=tail[i];
    }
    compress8(st,p); if(pad==128){for(i=0;i<8;++i)p[i]=tail[i]+64;compress8(st,p);}
    for(i=0;i<8;++i)for(j=0;j<8;++j)sm3_store_be32(out[i]+4*j,st[i][j]);
}

/* AVX-512 version is generated separately below with the same round structure. */
#define VROL512(x,n) _mm512_or_si512(_mm512_slli_epi32((x),(n)),_mm512_srli_epi32((x),32-(n)))
#define VX512(a,b,c) _mm512_xor_si512(_mm512_xor_si512((a),(b)),(c))
__attribute__((target("avx512f")))
static void compress16(uint32_t st[16][8], const uint8_t *p[16])
{
    __m512i w[68],a,b,c,d,e,f,g,h,o[8]; uint32_t x[16]; int i,j;
    for(j=0;j<16;++j){for(i=0;i<16;++i)x[i]=sm3_load_be32(p[i]+4*j);w[j]=_mm512_loadu_si512(x);}
    for(j=16;j<68;++j){__m512i q=VX512(w[j-16],w[j-9],VROL512(w[j-3],15));w[j]=VX512(VX512(q,VROL512(q,15),VROL512(q,23)),VROL512(w[j-13],7),w[j-6]);}
#define L16(k) _mm512_set_epi32(st[15][k],st[14][k],st[13][k],st[12][k],st[11][k],st[10][k],st[9][k],st[8][k],st[7][k],st[6][k],st[5][k],st[4][k],st[3][k],st[2][k],st[1][k],st[0][k])
    a=o[0]=L16(0);b=o[1]=L16(1);c=o[2]=L16(2);d=o[3]=L16(3);e=o[4]=L16(4);f=o[5]=L16(5);g=o[6]=L16(6);h=o[7]=L16(7);
    for(j=0;j<64;++j){__m512i tj=_mm512_set1_epi32((int)sm3_rol32(j<16?0x79cc4519U:0x7a879d8aU,j)),ar=VROL512(a,12),ss1=VROL512(_mm512_add_epi32(_mm512_add_epi32(ar,e),tj),7),ss2=_mm512_xor_si512(ss1,ar),ff,gg,t1,t2;
        if(j<16){ff=VX512(a,b,c);gg=VX512(e,f,g);}else{ff=_mm512_or_si512(_mm512_or_si512(_mm512_and_si512(a,b),_mm512_and_si512(a,c)),_mm512_and_si512(b,c));gg=_mm512_or_si512(_mm512_and_si512(e,f),_mm512_andnot_si512(e,g));}
        t1=_mm512_add_epi32(_mm512_add_epi32(ff,d),_mm512_add_epi32(ss2,_mm512_xor_si512(w[j],w[j+4])));
        t2=_mm512_add_epi32(_mm512_add_epi32(gg,h),_mm512_add_epi32(ss1,w[j]));
        d=c;c=VROL512(b,9);b=a;a=t1;h=g;g=VROL512(f,19);f=e;e=VX512(t2,VROL512(t2,9),VROL512(t2,17));}
    {__m512i z[8]={a,b,c,d,e,f,g,h};for(j=0;j<8;++j){o[j]=_mm512_xor_si512(o[j],z[j]);_mm512_storeu_si512(x,o[j]);for(i=0;i<16;++i)st[i][j]=x[i];}}
#undef L16
}
__attribute__((target("avx512f")))
static void hash16(const uint8_t *const d[16],size_t len,uint8_t out[16][32])
{
    uint32_t st[16][8];uint8_t tail[16][128];const uint8_t*p[16];size_t full=len&~(size_t)63,rem=len-full,pad=rem<56?64:128,off,i,j;
    for(i=0;i<16;++i)memcpy(st[i],sm3_iv,32);
    for(off=0;off<full;off+=64){for(i=0;i<16;++i)p[i]=d[i]+off;compress16(st,p);}
    for(i=0;i<16;++i){memset(tail[i],0,pad);if(rem)memcpy(tail[i],d[i]+full,rem);tail[i][rem]=0x80;for(j=0;j<8;++j)tail[i][pad-1-j]=(uint8_t)(((uint64_t)len*8)>>(8*j));p[i]=tail[i];}
    compress16(st,p);if(pad==128){for(i=0;i<16;++i)p[i]=tail[i]+64;compress16(st,p);}for(i=0;i<16;++i)for(j=0;j<8;++j)sm3_store_be32(out[i]+4*j,st[i][j]);
}

int sm3_hash_many_avx2(const uint8_t *const d[],size_t n,size_t len,uint8_t out[][32])
{size_t i=0;for(;i+8<=n;i+=8)hash8(d+i,len,out+i);for(;i<n;++i)sm3_hash(d[i],len,out[i]);return 0;}
int sm3_hash_many_avx512(const uint8_t *const d[],size_t n,size_t len,uint8_t out[][32])
{size_t i=0;for(;i+16<=n;i+=16)hash16(d+i,len,out+i);for(;i<n;++i)sm3_hash(d[i],len,out[i]);return 0;}
#else
int sm3_hash_many_avx2(const uint8_t *const d[],size_t n,size_t l,uint8_t o[][32]){(void)d;(void)n;(void)l;(void)o;return -1;}
int sm3_hash_many_avx512(const uint8_t *const d[],size_t n,size_t l,uint8_t o[][32]){(void)d;(void)n;(void)l;(void)o;return -1;}
#endif
