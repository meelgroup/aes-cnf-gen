# AES CNF generator

To gnerate a CNF file, simply execute:

```
./aesgen.py NUM_KEYBITS output.cnf --seed SEED
```

Which will generate a file that:
- Has `NUM_KEYBITS` key bits randomly picked from the 128 key bits, and set to random values.
- If you want the key variables to be set correctly (and hence generate a guaranteed satisfiable problem), set the option `--sat`
- Has a randomly picked `plaintext` set
- Has a randomly picked key that is used to encrypt `plaintext` and set as the ciphertext
- All the above randomness' seed can be set by setting `SEED`
- The CNF output is in `output.cnf`

As the `NUM_KEYBITS` gets smaller and smaller, the generated CNF file gets harder and harder to solve. Note that as `NUM_KEYBITS` approaches 128, the problem is extremely likley to be UNSAT unless you gave the `--sat` option

# How to test and generate sboxes

How to generate sboxes, test, etc.:
- Compile CryptoMiniSat, symlink it here: `ln -s ../cryptominisat/build/cryptominisat5 .`
- Run `git submodule init`, `git submodule update`
- `cd espresso-logic/espresso-src/`, `make`, `ln -s ../bin/espresso ../../espresso`
- Now you can run `./aesgen.py` with the test/sboxgen systems
