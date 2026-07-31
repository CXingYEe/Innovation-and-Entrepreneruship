#include "sm3_internal.h"

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#include <string.h>
#define R(x,n) vorrq_u32(vshlq_n_u32((x),(n)),vshrq_n_u32((x),32-(n)))
#define X(a,b,c) veorq_u32(veorq_u32((a),(b)),(c))
static void compress4(uint32_t st[4][8],const uint8_t*p[4])
{
 uint32x4_t w[68],a,b,c,d,e,f,g,h,o[8];uint32_t x[4];int i,j;
 for(j=0;j<16;++j){for(i=0;i<4;++i)x[i]=sm3_load_be32(p[i]+4*j);w[j]=vld1q_u32(x);}
 for(j=16;j<68;++j){uint32x4_t q=X(w[j-16],w[j-9],R(w[j-3],15));w[j]=X(X(q,R(q,15),R(q,23)),R(w[j-13],7),w[j-6]);}
#define L(k) ((uint32x4_t){st[0][k],st[1][k],st[2][k],st[3][k]})
 a=o[0]=L(0);b=o[1]=L(1);c=o[2]=L(2);d=o[3]=L(3);e=o[4]=L(4);f=o[5]=L(5);g=o[6]=L(6);h=o[7]=L(7);
 for(j=0;j<64;++j){uint32x4_t tj=vdupq_n_u32(sm3_rol32(j<16?0x79cc4519U:0x7a879d8aU,j)),ar=R(a,12),ss1=R(vaddq_u32(vaddq_u32(ar,e),tj),7),ss2=veorq_u32(ss1,ar),ff,gg,t1,t2;
  if(j<16){ff=X(a,b,c);gg=X(e,f,g);}else{ff=vorrq_u32(vorrq_u32(vandq_u32(a,b),vandq_u32(a,c)),vandq_u32(b,c));gg=vorrq_u32(vandq_u32(e,f),vbicq_u32(g,e));}
  t1=vaddq_u32(vaddq_u32(ff,d),vaddq_u32(ss2,veorq_u32(w[j],w[j+4])));t2=vaddq_u32(vaddq_u32(gg,h),vaddq_u32(ss1,w[j]));
  d=c;c=R(b,9);b=a;a=t1;h=g;g=R(f,19);f=e;e=X(t2,R(t2,9),R(t2,17));}
 {uint32x4_t z[8]={a,b,c,d,e,f,g,h};for(j=0;j<8;++j){vst1q_u32(x,veorq_u32(o[j],z[j]));for(i=0;i<4;++i)st[i][j]=x[i];}}
#undef L
}
static void hash4(const uint8_t*const d[4],size_t len,uint8_t out[4][32])
{uint32_t st[4][8];uint8_t tail[4][128];const uint8_t*p[4];size_t full=len&~(size_t)63,rem=len-full,pad=rem<56?64:128,off,i,j;
 for(i=0;i<4;++i) memcpy(st[i],sm3_iv,32);
 for(off=0;off<full;off+=64){for(i=0;i<4;++i)p[i]=d[i]+off;compress4(st,p);}
 for(i=0;i<4;++i){memset(tail[i],0,pad);if(rem)memcpy(tail[i],d[i]+full,rem);tail[i][rem]=0x80;for(j=0;j<8;++j)tail[i][pad-1-j]=(uint8_t)(((uint64_t)len*8)>>(8*j));p[i]=tail[i];}
 compress4(st,p);if(pad==128){for(i=0;i<4;++i)p[i]=tail[i]+64;compress4(st,p);}for(i=0;i<4;++i)for(j=0;j<8;++j)sm3_store_be32(out[i]+4*j,st[i][j]);}
int sm3_hash_many_neon(const uint8_t*const d[],size_t n,size_t len,uint8_t out[][32])
{size_t i=0;for(;i+4<=n;i+=4)hash4(d+i,len,out+i);for(;i<n;++i)sm3_hash(d[i],len,out[i]);return 0;}
#else
int sm3_hash_many_neon(const uint8_t*const d[],size_t n,size_t l,uint8_t o[][32]){(void)d;(void)n;(void)l;(void)o;return -1;}
#endif
