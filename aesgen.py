#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 Mate Soos
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.


# based on the Wikipedia Article https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
# Also see https://gist.github.com/bonsaiviking/5571001
#        self.nb = 4
#        self.nr = 10
#        self.nk = 4


import os
import sys
import time
import random
import numpy as np


def fill_sbox(cl, vs, out):
    this_cl = str(cl)
    for i in range(8):
        this_cl = this_cl.replace("x(%d) " % i, "%d " % vs[i])

    this_cl = this_cl.replace("y", "%d 0" % out)
    this_cl.replace("--", "")
    return this_cl

def get_n_sat_solutions(fname, num):
    fname_out = "test.out"
    os.system("./cryptominisat5 %s > %s --maxsol %d 2>&1" % (fname, fname_out, num))
    solutions = []
    num_sat = 0
    solution_found = False
    with open(fname_out, "r") as f:
        for line in f:
            line = line.strip()
            if "ERROR" in line:
                print("Error in CNF?!, file: ", fname)
                exit(-1)
            if len(line) == 0:
                continue
            if line[0] == "c":
                continue
            if line[0] == "s":
                if "s SATISFIABLE" in line:
                    if solution_found:
                        solutions.append(solution)
                    num_sat += 1
                    solution = {}
                    solution_found = True
            if line[0] == "v":
                assert num_sat == 1
                for lit in line.split():
                    if lit == "v":
                        continue
                    lit = int(lit)
                    if lit == 0:
                        continue
                    solution[abs(lit)] = lit > 0

    if solution_found:
        solutions.append(solution)

    os.unlink(fname_out)
    return solutions

class SBoxGen:
    def __init__(self):
        self.sbox_orig = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]


    # let's use https://github.com/classabbyamp/espresso-logic
    # to generate S-box
    # It's effectively 8 functions, each f(8bits) -> 1 bit output

    # generates truth table that outputs the bit desired,
    # needed to define both 1 and 0 outputs
    def gen_espresso(self, bit, out_bit_val):
        fname = "input-bit-%d-outval-%d.esp" % (bit, out_bit_val)
        with open(fname, "w") as f:
            f.write(".i 8\n")
            f.write(".o 1\n")
            for i in range(256):
                out_val = (self.sbox_orig[i]>>bit)&1
                for i2 in range(8):
                    in_val = (i>>i2)&1
                    f.write("%d" % in_val)

                f.write(" %d\n" % (out_bit_val == out_val))
            f.write(".e\n")

        #print("Wrote file %s" % fname)
        return fname

    # generate set of clauses based on output of espresso
    # the invert option is to allow it to define both 1 and 0 outputs
    def one_espresso_set(self, fname, invert):
        clauses = []
        out_fname = fname+".out"
        os.system("./espresso %s > %s" % (fname, out_fname))
        with open(out_fname, "r") as f:
            for line in f:
                clause = ""
                line = line.strip()
                if len(line) == 0:
                    continue
                if line[0] == ".":
                    continue
                assert len(line) == 8+1+1
                for i in range(8):
                    if line[i] == "-":
                        continue
                    assert line[i] == "0" or line[i] == "1"
                    if line[i] == "0":
                        clause+="x(%d) " % i
                    else:
                        clause+="-x(%d) " % i

                assert line[9] == "1"
                clause+="%sy" % invert
                #print("line: '%s', clause: %s" % (line, clause))
                clauses.append(clause)


        return clauses

    def create_sboxes(self):
        print("Creating SBoxes using espresso...")
        # variables are going to be x0..x7, output: y
        sbox = []
        for bit in range(8):
            fname = {}
            for val in range(2):
                fname[val] = self.gen_espresso(bit, val)

            clauses = self.one_espresso_set(fname[1], "")
            clauses.extend(self.one_espresso_set(fname[0], "-"))
            sbox.append(clauses)

            for val in range(2):
                os.unlink(fname[val])

        print("Done.")
        return sbox


    def test_sbox(self, at, sbox):
        print("Testing sbox that computes bit %d given input value", at)
        vs = range(1,9)
        out = 9
        final_cls = []
        for cl in sbox[at]:
            this_cl = fill_sbox(cl, vs, out)
            final_cls.append(this_cl)

        for testval in range(256):
            print("Testing input value %d" % testval)
            fname = "test.cnf"
            with open(fname, "w") as f:
                for cl in final_cls:
                    f.write(cl+"\n")
                for i in range(8):
                    val = (testval>>i)&1
                    if val == 0:
                        f.write("-%d 0\n" % vs[i])
                    else:
                        f.write("%d 0\n" % vs[i])

            expected_val = (self.sbox_orig[testval]>>at)&1
            # 'out' is supposed to take value
            # there is only supposed to be a single
            print("Created file %s to check output" % fname)
            solutions = get_n_sat_solutions(fname, 1000)
            assert len(solutions) == 1
            solution = solutions[0]
            print("solution[out]: ", solution[out])
            print("expected_val: " , expected_val)
            assert solution[out] == expected_val
            # TODO check number of solutions! Should be ONE
            os.unlink(fname)

    def test(self):
        sbox = self.create_sboxes()
        assert len(sbox) == 8
        for i in range(8):
            self.test_sbox(i, sbox)

class AESNormKS:
    def __init__(self):
        self.sbox = np.array([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],dtype=np.uint8)

        self.rcon = np.array([0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a],dtype=np.uint8)

    def rotate(self, v):
      tmp = v[0]; v[0:3] = v[1:]; v[3] = tmp;

    #expand a 16-byte AES key
    def ks_expand(self, key,n=16,b=176):
      expanded_key = np.zeros(b,dtype=np.uint8);
      #set the first 16 bytes to the original key
      expanded_key[0:16] = key;
      #continue adding 16 bytes until b bytes have been generated
      i = 1; j = 16;
      while (j < b):
        tmp = np.copy(expanded_key[j-4:j]);
        self.rotate(tmp);
        tmp = np.vectorize(lambda x: self.sbox[x])(tmp);
        tmp[0] = tmp[0] ^ self.rcon[i];
        tmp = tmp ^ expanded_key[j-n:j-n+4];
        expanded_key[j:j+4] = np.copy(tmp);
        for offset in range(j+4,j+16,4):
          tmp = expanded_key[offset-n:offset-n+4] ^ tmp;
          expanded_key[offset:offset+4] = np.copy(tmp);
        j = j + 16; i = i + 1;
      return(expanded_key);


class AES:
    def __init__(self, sbox, fname):
        self.sbox = sbox
        self.rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]
        self.v = 1
        self.cnf = open(fname, "w")

    def get_n_vars(self, n):
        ret = list(range(self.v, self.v+n))
        self.v += n

        return ret

    def add_base_vars(self):
        self.key = self.get_n_vars(128)
        self.plaintext = self.get_n_vars(128)
        self.ciphertext = self.get_n_vars(128)

    def rotate(self, tmp):
      assert len(tmp) == 4*8

      ret = [0]*len(tmp)
      ret[0:3*8] = list(tmp[1*8:])
      ret[3*8:] = list(tmp[0:1*8])

      return ret


    def xor_clause(self, vs, rhs):
        assert type(vs) == list

        toprint = "x"
        for i in range(len(vs)):
            # default rhs is TRUE
            if i == 0:
                if not rhs:
                    toprint+="%d " % -vs[i]
                else:
                    toprint+="%d " % vs[i]
            else:
                toprint+="%d " % vs[i]

        toprint +="0\n"
        self.cnf.write(toprint)


    def do_xor(self, vs):
        assert type(vs) == list

        tmp = self.get_n_vars(1)[0]
        self.xor_clause(vs+[tmp], False)
        return tmp

    def binary_invert(self, lit, inv):
        assert type(inv) is bool or inv == 0 or inv == 1

        if inv:
            return -lit
        else:
            return lit

    def sbox_clauses(self, vs):
        outs = self.get_n_vars(8)
        for i in range(8):
            out = outs[i]
            for cl in self.sbox[i]:
                this_cl = fill_sbox(cl, vs, out)
                self.cnf.write(this_cl+"\n")

        return outs


    # NOTE: first 192 are OK, rest are wrong
    # 192-128 = 64 bits are OK, i.e. 8 bytes


    # from https://github.com/agohr/ches2018/blob/master/sources/aes_ks.py
    # expand a 16-byte, i.e. 128b AES key
    # 10-round AES, with 1 extra round needed at the end, hence 128*11 bits
    def ks_expand(self, b=128*11):
        expanded_key = self.get_n_vars(b)

        #set the first 16 bytes to the original key
        expanded_key[0:128] = list(self.key)
        #continue adding 16 bytes until b bits have been generated
        i = 1
        j = 128
        while (j < b):
            # tmp is 4 bytes (i.e. 32 bits), bytes 12...15 in expanded_key
            tmp = list(expanded_key[j-4*8:j])
            tmp = self.rotate(tmp)

            for h in range(4):
                tmp[h*8:h*8+8] = self.sbox_clauses(tmp[h*8:h*8+8])

            # xor only the 1st byte with rcon
            for k in range(8):
                #print("i:", i)
                #print("k:", k)
                #print("j:", j)
                #print("b:", b)
                #print("tmp[k]:", tmp[k])
                #print("self.rcon[i]:", self.rcon[i])
                tmp[k] = self.binary_invert(tmp[k], (self.rcon[i]>>k)&1)

            # for all bytes
            # tmp = tmp ^ expanded_key[j-n:j-n+4]; -- where n = 16
            for k in range(4*8):
                tmp[k] = self.do_xor([tmp[k], expanded_key[j-128+k]])

            # set 4 bytes
            expanded_key[j:j+4*8] = list(tmp)

            # set 12 more bytes
            for offset in range(j+4*8, j+128, 4*8):
                for k in range(4*8):
                    tmp[k] = self.do_xor([expanded_key[offset-128+k], tmp[k]])
                    expanded_key[offset+k] = tmp[k]

            j += 128
            i += 1

        return expanded_key


def test_key_expansion(sbox):
    key = []
    for i in range(16):
        byte = random.getrandbits(8)
        key.append(byte)
    print("Key is: ", key)

    norm = AESNormKS()
    good_exp_key = norm.ks_expand(key)
    print("Extended key is: ", good_exp_key)


    # create aes.cnf to get extended key
    fname = "aes.cnf"
    aes = AES(sbox, fname)
    aes.add_base_vars()
    expanded_key_vars = aes.ks_expand()
    #print("expanded_key_vars:", expanded_key_vars)
    assert len(expanded_key_vars) == 8*len(good_exp_key)

    # add key to CNF and get solution
    for i in range(128):
        v = ((key[i//8])>>(i%8))&1
        #print("Key bit %s is %s" % (i, v))
        if v:
            aes.cnf.write("%d 0\n" % aes.key[i])
        else:
            aes.cnf.write("-%d 0\n" % aes.key[i])
    aes.cnf.close()
    solutions = get_n_sat_solutions(fname, 1)
    assert len(solutions) == 1
    solution = solutions[0]

    # check solution
    # bint 19
    for i in range(8*len(good_exp_key)):
        v = expanded_key_vars[i]
        value = solution[v]
        good_value = (good_exp_key[i//8]>>(i%8))&1
        #print("value     :", value)
        #print("good value:", good_value)
        if good_value != value:
            print("At bit: %d incorrect value" % i)
        assert good_value == value

    print("Test OK")

if __name__ == "__main__":
    sboxgen = SBoxGen()
    #sboxgen.test()
    random.seed(1)
    sboxgen = SBoxGen()
    sbox = sboxgen.create_sboxes()
    for test_no in range(100):
        test_key_expansion(sbox)


















