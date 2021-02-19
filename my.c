#include <stdio.h>

extern int myfce(int a, int b)
{
  return (a+b);
}

#if 0
int main(int argc, char *argv[])
{
  printf("Test: %d\n", myfce(5,53));
}
#endif
