#include <string.h>

#include "../pbkdf2.h"
#include "test.h"

/* Reference values computed with Python's hashlib.pbkdf2_hmac, using the
 * salt "0123456789abcdef", the password "secret" and 1000 iterations. */
#define SALT "MDEyMzQ1Njc4OWFiY2RlZg=="
#define SHA512_HASH "vgFvU7zWIDgDAUi7d8ayt+cfRiPWVVWfv8iQRsGZaZs="
#define SHA256_HASH "tiKWHy4FAGCWE8gn6GtKhaxD2OeeAUUWXFT/p1aaNl8="
#define SHA512_HASH_64 "vgFvU7zWIDgDAUi7d8ayt+cfRiPWVVWfv8iQRsGZaZviWzsSNgWYXEE5PmvI/VELMsOmEbqLz0PKuePNjOk41A=="

static void test_known_vectors(void)
{
	CHECK(pbkdf2_verify("secret", "PBKDF2$sha512$1000$" SALT "$" SHA512_HASH));
	CHECK(!pbkdf2_verify("Secret", "PBKDF2$sha512$1000$" SALT "$" SHA512_HASH));
	CHECK(!pbkdf2_verify("", "PBKDF2$sha512$1000$" SALT "$" SHA512_HASH));
	CHECK(pbkdf2_verify("secret", "PBKDF2$sha256$1000$" SALT "$" SHA256_HASH));
	/* Wrong algorithm for the hash */
	CHECK(!pbkdf2_verify("secret", "PBKDF2$sha256$1000$" SALT "$" SHA512_HASH));
	/* Wrong iteration count */
	CHECK(!pbkdf2_verify("secret", "PBKDF2$sha512$1001$" SALT "$" SHA512_HASH));
}

static void test_phc_format(void)
{
	CHECK(pbkdf2_verify("secret", "pbkdf2-sha512$i=1000,l=32$" SALT "$" SHA512_HASH));
	CHECK(pbkdf2_verify("secret", "pbkdf2-sha512$i=1000,l=64$" SALT "$" SHA512_HASH_64));
	CHECK(!pbkdf2_verify("wrong", "pbkdf2-sha512$i=1000,l=32$" SALT "$" SHA512_HASH));
	/* The key length must match the stored hash */
	CHECK(!pbkdf2_verify("secret", "pbkdf2-sha512$i=1000,l=64$" SALT "$" SHA512_HASH));
	/* The key length is optional */
	CHECK(pbkdf2_verify("secret", "pbkdf2-sha512$i=1000$" SALT "$" SHA512_HASH));
}

static void test_unpadded_base64(void)
{
	CHECK(pbkdf2_verify("secret",
			"PBKDF2$sha512$1000$MDEyMzQ1Njc4OWFiY2RlZg$vgFvU7zWIDgDAUi7d8ayt+cfRiPWVVWfv8iQRsGZaZs"));
}

static void test_create_roundtrip(void)
{
	char a[256], b[256];

	CHECK(pbkdf2_create("hunter2", 1000, a, sizeof(a)) == 0);
	CHECK(!strncmp(a, "PBKDF2$sha512$1000$", strlen("PBKDF2$sha512$1000$")));
	CHECK(pbkdf2_hash_valid(a));
	CHECK(pbkdf2_verify("hunter2", a));
	CHECK(!pbkdf2_verify("hunter3", a));

	/* A fresh random salt per hash */
	CHECK(pbkdf2_create("hunter2", 1000, b, sizeof(b)) == 0);
	CHECK(strcmp(a, b) != 0);
	CHECK(pbkdf2_verify("hunter2", b));

	/* Non-ASCII and colons in passwords */
	CHECK(pbkdf2_create("pä:ss$wörd", 1000, a, sizeof(a)) == 0);
	CHECK(pbkdf2_verify("pä:ss$wörd", a));
	CHECK(!pbkdf2_verify("pä:ss", a));

	CHECK(pbkdf2_create("", 1000, a, sizeof(a)) == 0);
	CHECK(pbkdf2_verify("", a));
	CHECK(!pbkdf2_verify("x", a));
}

static void test_create_errors(void)
{
	char small[16];

	CHECK(pbkdf2_create("pw", 1000, small, sizeof(small)) == -1);
	CHECK(pbkdf2_create("pw", 0, small, sizeof(small)) == -1);
}

static void test_invalid_hashes(void)
{
	static const char *bad[] = {
		"",
		"plaintext",
		"PBKDF2",
		"PBKDF2$sha512",
		"PBKDF2$sha512$1000",
		"PBKDF2$sha512$1000$" SALT,
		"PBKDF2$md5$1000$" SALT "$" SHA512_HASH,
		"PBKDF2$sha512$abc$" SALT "$" SHA512_HASH,
		"PBKDF2$sha512$0$" SALT "$" SHA512_HASH,
		"PBKDF2$sha512$-5$" SALT "$" SHA512_HASH,
		"PBKDF2$sha512$1000$!!!!$" SHA512_HASH,
		"PBKDF2$sha512$1000$" SALT "$!!!!",
		"PBKDF2$sha512$1000$$",
		"pbkdf2-sha512$l=32$" SALT "$" SHA512_HASH,
		"pbkdf2-sha512$i=x,l=32$" SALT "$" SHA512_HASH,
		"$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234",
	};

	for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++){
		if(pbkdf2_hash_valid(bad[i])){
			fprintf(stderr, "unexpectedly valid: \"%s\"\n", bad[i]);
		}
		CHECK(!pbkdf2_hash_valid(bad[i]));
		CHECK(!pbkdf2_verify("secret", bad[i]));
	}

	CHECK(pbkdf2_hash_valid("PBKDF2$sha512$1000$" SALT "$" SHA512_HASH));
	CHECK(pbkdf2_hash_valid("PBKDF2$sha256$1000$" SALT "$" SHA256_HASH));
	CHECK(pbkdf2_hash_valid("pbkdf2-sha512$i=1000,l=32$" SALT "$" SHA512_HASH));
}

static void test_oversized_input(void)
{
	char big[8192];

	memset(big, 'A', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	CHECK(!pbkdf2_hash_valid(big));
	CHECK(!pbkdf2_verify("secret", big));
}

int main(void)
{
	test_known_vectors();
	test_phc_format();
	test_unpadded_base64();
	test_create_roundtrip();
	test_create_errors();
	test_invalid_hashes();
	test_oversized_input();
	TEST_DONE();
}
