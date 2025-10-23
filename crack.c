/* crack.c
 *
 * Dictionary-based MD5 hash cracker for the assignment.
 *
 * Usage: ./crack <hash_file> <dictionary_file>
 *
 * Depends on md5(const char *str, int length) provided in md5.c / md5.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

#define MAX_LINE 4096
#define HASH_LEN 33   /* 32 hex chars + '\0' */

/* Remove trailing newline and carriage return from string in place */
static void chomp(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        --len;
    }
}

/*
 * tryWord:
 *   Given a plaintext word and a hash filename, compute the MD5 hex digest
 *   for the plaintext and search the file for a matching hash.
 *
 * Returns:
 *   - a malloc'd string containing the matching hash (caller must free),
 *     if the hash is found in hashFilename.
 *   - NULL if not found or on error.
 *
 * Note: md5(...) returns a malloc'd string; we free that after using it.
 */
char * tryWord(char * plaintext, char * hashFilename)
{
    if (plaintext == NULL || hashFilename == NULL) return NULL;

    /* compute md5 hex for plaintext */
    char *digest = md5(plaintext, (int)strlen(plaintext));
    if (digest == NULL) {
        return NULL;
    }

    /* open hash file */
    FILE *hf = fopen(hashFilename, "r");
    if (!hf) {
        perror("Error opening hash file in tryWord");
        free(digest);
        return NULL;
    }

    char line[MAX_LINE];
    char *found_hash = NULL;

    /* iterate through hash file lines */
    while (fgets(line, sizeof(line), hf)) {
        chomp(line);
        if (line[0] == '\0') continue;

        /* compare digest to this line; assume hashes are lowercase (as usual) */
        if (strcmp(digest, line) == 0) {
            /* match: return a malloc'd copy of the matched hash */
            found_hash = strdup(line);
            break;
        }
    }

    fclose(hf);
    free(digest);

    return found_hash; /* may be NULL if no match */
}

int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    char *hashFilename = argv[1];
    char *dictFilename = argv[2];

    /* -- Test that tryWord works with "hello" and hashes00.txt --
       The assignment suggests you first test tryWord this way.
       The real MD5 of "hello" is:
         5d41402abc4b2a76b9719d911017c592
    */
    char *found = tryWord("hello", "hashes00.txt");
    if (found) {
        printf("%s %s\n", found, "hello");
        free(found);
    } else {
        printf("hello not found in hashes00.txt (tryWord test)\n");
    }

    /* Now crack using the provided dictionary file.
       For each dictionary word, call tryWord(word, hashFilename).
       Keep track of hashes we've already cracked to avoid duplicate printing.
    */

    FILE *df = fopen(dictFilename, "r");
    if (!df) {
        perror("Error opening dictionary file");
        return 1;
    }

    /* We'll keep a dynamic list of cracked hashes so we don't print duplicates */
    size_t cracked_cap = 128;
    size_t cracked_count = 0;
    char **cracked = malloc(cracked_cap * sizeof(char*));
    if (!cracked) {
        perror("malloc");
        fclose(df);
        return 1;
    }

    char line[MAX_LINE];
    size_t total_cracked = 0;

    while (fgets(line, sizeof(line), df)) {
        chomp(line);
        if (line[0] == '\0') continue; /* skip empty */

        /* call tryWord which will open and search the hash file for us */
        char *match = tryWord(line, hashFilename);
        if (match) {
            /* check if this hash was already printed/cracked */
            int already = 0;
            for (size_t i = 0; i < cracked_count; ++i) {
                if (strcmp(match, cracked[i]) == 0) {
                    already = 1;
                    break;
                }
            }
            if (!already) {
                printf("%s %s\n", match, line);
                /* record it */
                if (cracked_count >= cracked_cap) {
                    size_t nc = cracked_cap * 2;
                    char **tmp = realloc(cracked, nc * sizeof(char*));
                    if (!tmp) {
                        perror("realloc");
                        free(match);
                        break;
                    }
                    cracked = tmp;
                    cracked_cap = nc;
                }
                cracked[cracked_count++] = match; /* keep ownership of match */
                total_cracked++;
            } else {
                /* already recorded - free the returned duplicate */
                free(match);
            }
        }
    }

    fclose(df);

    printf("%zu hashes cracked!\n", total_cracked);

    /* cleanup */
    for (size_t i = 0; i < cracked_count; ++i) free(cracked[i]);
    free(cracked);

    return 0;
}
