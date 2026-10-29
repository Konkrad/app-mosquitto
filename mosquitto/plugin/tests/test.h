/* Minimal test helpers: CHECK() records failures and keeps going. */
#ifndef HA_AUTH_TEST_H
#define HA_AUTH_TEST_H

#include <stdio.h>

static int test_failures;
static int test_checks;

#define CHECK(cond) do { \
	test_checks++; \
	if(!(cond)){ \
		test_failures++; \
		fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while(0)

#define TEST_DONE() do { \
	printf("%s: %d checks, %d failed\n", __FILE__, test_checks, test_failures); \
	return test_failures ? 1 : 0; \
} while(0)

#endif
