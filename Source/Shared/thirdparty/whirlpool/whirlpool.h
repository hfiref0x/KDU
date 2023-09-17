#include "nessie.h"

void NESSIEinit(struct NESSIEstruct* const structpointer);
void NESSIEadd(const unsigned char* const source, unsigned long sourceBits, struct NESSIEstruct* const structpointer);
void NESSIEfinalize(struct NESSIEstruct* const structpointer, unsigned char* const result);
