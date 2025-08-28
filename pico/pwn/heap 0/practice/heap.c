#include <stdio.h>
#include <stdlib.h>

char password[] = "250382";

int main(int argc, char *argv[])
{
  char *buf = (char *)malloc(100);
  char *secret = (char *)malloc(100);

  strcpy(secret, password);

  printf("IOLI Crackme Level 0x00\n");
  printf("Password:");

  scanf("%s", buf);

  if (!strcmp(buf, secret)) {
    printf("Password OK :)\n");
  } else {
    printf("Invalid Password! %s\n", buf);
  }

  return 0;
}
