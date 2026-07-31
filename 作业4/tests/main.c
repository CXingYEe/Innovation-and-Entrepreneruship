#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void hex(char dst[65],const uint8_t x[32])
{static const char h[]="0123456789abcdef";int i;for(i=0;i<32;++i){dst[2*i]=h[x[i]>>4];dst[2*i+1]=h[x[i]&15];}dst[64]=0;}

static int parse_impl(const char *name, sm3_impl *impl)
{
 sm3_impl i;
 for(i=SM3_IMPL_SCALAR;i<=SM3_IMPL_NEON;++i)
  if(!strcmp(name,sm3_impl_name(i))){*impl=i;return 1;}
 return 0;
}

static size_t impl_lanes(sm3_impl impl)
{
 return impl==SM3_IMPL_AVX512?16:impl==SM3_IMPL_AVX2?8:
        impl==SM3_IMPL_NEON?4:1;
}

static int hash_command(sm3_impl impl,const char *text)
{
 const uint8_t *p[16];uint8_t out[16][32],ref[32];char digest[65];
 size_t i,n=impl_lanes(impl),len=strlen(text);
 if(!sm3_impl_available(impl)){
  fprintf(stderr,"error: %s is unavailable on this CPU/architecture\n",sm3_impl_name(impl));
  return 1;
 }
 for(i=0;i<n;++i)p[i]=(const uint8_t*)text;
 sm3_hash_many(impl,p,n,len,out);
 sm3_hash((const uint8_t*)text,len,ref);
 hex(digest,out[0]);
 printf("SM3 hash result\n");
 printf("  architecture : %s\n",
#if defined(__aarch64__) || defined(_M_ARM64)
        "ARM64"
#elif defined(__x86_64__) || defined(_M_X64)
        "x86-64"
#else
        "other"
#endif
 );
 printf("  implementation: %s\n",sm3_impl_name(impl));
 printf("  SIMD lanes    : %zu\n",n);
 printf("  input (UTF-8) : \"%s\"\n",text);
 printf("  input length  : %zu bytes\n",len);
 printf("  SM3 digest    : %s\n",digest);
 printf("  scalar check  : %s\n",memcmp(ref,out[0],32)?"FAIL":"PASS");
 return memcmp(ref,out[0],32)!=0;
}

static int compare_command(const char *text)
{
 sm3_impl list[2];uint8_t scalar[32],out[16][32];const uint8_t*p[16];
 char a[65],b[65];size_t i,n,len=strlen(text);sm3_impl opt;
#if defined(__aarch64__) || defined(_M_ARM64)
 opt=SM3_IMPL_NEON;
#elif defined(__x86_64__) || defined(_M_X64)
 opt=sm3_impl_available(SM3_IMPL_AVX512)?SM3_IMPL_AVX512:SM3_IMPL_AVX2;
#else
 opt=SM3_IMPL_SCALAR;
#endif
 list[0]=SM3_IMPL_SCALAR;list[1]=opt;
 sm3_hash((const uint8_t*)text,len,scalar);hex(a,scalar);
 n=impl_lanes(list[1]);for(i=0;i<n;++i)p[i]=(const uint8_t*)text;
 sm3_hash_many(list[1],p,n,len,out);hex(b,out[0]);
 printf("SM3 scalar/SIMD comparison\n");
 printf("  input (UTF-8) : \"%s\"\n",text);
 printf("  input length  : %zu bytes\n",len);
 printf("  scalar digest : %s\n",a);
 printf("  %-6s digest : %s\n",sm3_impl_name(list[1]),b);
 printf("  result        : %s\n",memcmp(scalar,out[0],32)?"FAIL":"MATCH (PASS)");
 return memcmp(scalar,out[0],32)!=0;
}

static int test_impl(sm3_impl impl)
{
 static const char expect[]="66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
 static const size_t lens[]={0,1,3,55,56,63,64,65,127,128,129,1024};
 const uint8_t *p[16];uint8_t out[16][32],ref[32],buf[16][1024];char s[65];
 size_t i,k,n=impl==SM3_IMPL_AVX512?16:impl==SM3_IMPL_AVX2?8:impl==SM3_IMPL_NEON?4:1;
 for(i=0;i<n;++i)p[i]=(const uint8_t*)"abc";
 if(sm3_hash_many(impl,p,n,3,out))return 0;
 for(i=0;i<n;++i){hex(s,out[i]);if(strcmp(s,expect))return 0;}
 for(i=0;i<n;++i){for(k=0;k<sizeof(buf[i]);++k)buf[i][k]=(uint8_t)(i*29+k*131+7);p[i]=buf[i];}
 for(k=0;k<sizeof(lens)/sizeof(lens[0]);++k){
  if(sm3_hash_many(impl,p,n,lens[k],out))return 0;
  for(i=0;i<n;++i){sm3_hash(p[i],lens[k],ref);if(memcmp(ref,out[i],32))return 0;}
 }
 return 1;
}
static void benchmark(sm3_impl impl)
{
 enum{N=16,L=4096,ROUNDS=2000};uint8_t *buf=malloc(N*L),out[N][32];const uint8_t*p[N];clock_t a,b;int i,r;double sec,mb;
 if(!buf)return;
 for(i=0;i<N*L;++i)buf[i]=(uint8_t)(i*131+17);
 for(i=0;i<N;++i)p[i]=buf+i*L;
 a=clock();for(r=0;r<ROUNDS;++r)sm3_hash_many(impl,p,N,L,out);b=clock();
 sec=(double)(b-a)/CLOCKS_PER_SEC;mb=(double)N*L*ROUNDS/1000000.0;
 printf("  %-7s %8.2f MB/s  (%.1f MB, %.3f s)\n",sm3_impl_name(impl),mb/sec,mb,sec);free(buf);
}
int main(int argc,char**argv)
{
 sm3_impl i;int failed=0,bench=argc>1&&!strcmp(argv[1],"bench");
 if(argc>=4&&!strcmp(argv[1],"hash")){
  if(!parse_impl(argv[2],&i)){fprintf(stderr,"usage: %s hash <scalar|avx2|avx512|neon> <text>\n",argv[0]);return 2;}
  return hash_command(i,argv[3]);
 }
 if(argc>=3&&!strcmp(argv[1],"compare"))return compare_command(argv[2]);
 if(argc>1&&strcmp(argv[1],"bench")){
  fprintf(stderr,"usage: %s [bench | hash <implementation> <text> | compare <text>]\n",argv[0]);return 2;
 }
 puts("SM3 scalar/SIMD implementation");
 for(i=SM3_IMPL_SCALAR;i<=SM3_IMPL_NEON;++i) {
  if(!sm3_impl_available(i)){printf("  %-7s unavailable on this CPU/architecture\n",sm3_impl_name(i));continue;}
  if(!test_impl(i)){printf("  %-7s FAIL\n",sm3_impl_name(i));failed=1;}else if(bench)benchmark(i);else printf("  %-7s PASS\n",sm3_impl_name(i));
 }
 return failed;
}
