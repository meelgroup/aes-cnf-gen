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
import random
import aes as otheraes
import aesnormks
import optparse
import pickle


def fill_sbox(cl, vs, out):
    this_cl = str(cl)
    for i in range(8):
        this_cl = this_cl.replace("x(%d) " % i, "%d " % vs[i])

    this_cl = this_cl.replace("y", "%d 0" % out)
    this_cl.replace("--", "")
    return this_cl

def get_n_sat_solutions(fname, num):
    fname_out = "test.out"
    os.system("./cryptominisat5 --maxsol %d %s > %s 2>&1" % (num, fname, fname_out))
    solutions = []
    num_sat = 0
    num_unsat = 0
    solution_found = False
    solution = None
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
                        assert solution is not None
                        solutions.append(solution)
                    num_sat += 1
                    solution = {}
                    solution_found = True
                    continue

                if "s UNSAT" in line:
                    num_unsat += 1
                    continue

            if line[0] == "v":
                assert num_sat == 1
                for lit in line.split():
                    if lit == "v":
                        continue
                    lit = int(lit)
                    if lit == 0:
                        continue
                    assert solution is not None
                    solution[abs(lit)] = lit > 0
                continue

            print("ERROR! This line is unrecognized: %s" % line)

    if solution_found:
        solutions.append(solution)

    os.unlink(fname_out)
    return solutions

class SBoxGen:
    def __init__(self):
        self.sbox_orig = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

        self.Gmul = {}
        for f in (0x02, 0x03):
            self.Gmul[f] = tuple(AESSAT.gmul(f, x) for x in range(0,0x100))

    # let's use https://github.com/classabbyamp/espresso-logic
    # to generate S-box
    # It's effectively 8 functions, each f(8bits) -> 1 bit output

    # generates truth table that outputs the bit desired,
    # needed to define both 1 and 0 outputs
    def gen_espresso(self, bit, out_bit_val, sbox):
        fname = "input-bit-%d-outval-%d.esp" % (bit, out_bit_val)
        with open(fname, "w") as f:
            f.write(".i 8\n")
            f.write(".o 1\n")
            for i in range(256):
                out_val = (sbox[i]>>bit)&1
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

    def create_sboxes(self, sbox):
        print("Creating SBoxes using espresso...")
        # variables are going to be x0..x7, output: y
        ret = []
        for bit in range(8):
            fname = {}
            for val in range(2):
                fname[val] = self.gen_espresso(bit, val, sbox)

            clauses = self.one_espresso_set(fname[1], "")
            clauses.extend(self.one_espresso_set(fname[0], "-"))
            ret.append(clauses)

            for val in range(2):
                os.unlink(fname[val])

        print("Done.")
        return ret

    def test_sbox(self, at, sbox, sbox_good):
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

            expected_val = (sbox_good[testval]>>at)&1
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
        sbox_gmul2 = self.create_sboxes(self.Gmul[0x02])
        assert len(sbox_gmul2) == 8
        for i in range(8):
            self.test_sbox(i, sbox_gmul2, self.Gmul[0x02])

        sbox_gmul3 = self.create_sboxes(self.Gmul[0x03])
        assert len(sbox_gmul3) == 8
        for i in range(8):
            self.test_sbox(i, sbox_gmul3, self.Gmul[0x03])

        sbox = self.create_sboxes(self.sbox_orig)
        assert len(sbox) == 8
        for i in range(8):
            self.test_sbox(i, sbox, self.sbox_orig)


class AESSAT:
    def __init__(self, sbox, sbox_gmul2, sbox_gmul3, fname):
        self.sbox = sbox
        self.rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]
        self.v = 1
        self.cnf = open(fname, "w")
        self.sbox_gmul2 = sbox_gmul2
        self.sbox_gmul3 = sbox_gmul3
        self.add_base_vars()

    @staticmethod
    def gmul(a, b):
        p = 0
        for c in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return p

    def get_n_vars(self, n):
        ret = list(range(self.v, self.v+n))
        self.v += n

        return ret

    def add_base_vars(self):
        self.key = self.get_n_vars(128)
        self.plaintext = self.get_n_vars(128)

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

    def do_xor_byte(self, vs):
        assert type(vs) == list
        for v in vs:
            assert type(v) == list
            assert len(v) == 8

        tmp = self.get_n_vars(8)
        for i in range(8):
            toxor = []
            toxor.append(tmp[i])
            for v in vs:
                toxor.append(v[i])
            self.xor_clause(toxor, False)
        return tmp

    def binary_invert(self, lit, inv):
        assert type(inv) is bool or inv == 0 or inv == 1

        if inv:
            return -lit
        else:
            return lit

    def sbox_clauses(self, vs, sbox):
        assert len(vs) == 8

        outs = self.get_n_vars(8)
        for i in range(8):
            out = outs[i]
            for cl in sbox[i]:
                this_cl = fill_sbox(cl, vs, out)
                self.cnf.write(this_cl+"\n")

        return outs


    # NOTE: first 192 are OK, rest are wrong
    # 192-128 = 64 bits are OK, i.e. 8 bytes


    # from https://github.com/agohr/ches2018/blob/master/sources/aes_ks.py
    # expand a 16-byte, i.e. 128b AES key
    # 10-round AES, with 1 extra round needed at the end, hence 128*11 bits
    def ks_expand(self, b=128*11):
        expanded_key = list(self.key) + [0]*(b-128)

        #set the first 16 bytes to the original key
        #expanded_key[0:128] = list(self.key)
        #continue adding 16 bytes until b bits have been generated
        i = 1
        j = 128
        while (j < b):
            # tmp is 4 bytes (i.e. 32 bits), bytes 12...15 in expanded_key
            tmp = list(expanded_key[j-4*8:j])
            tmp = self.rotate(tmp)

            for h in range(4):
                tmp[h*8:h*8+8] = self.sbox_clauses(tmp[h*8:h*8+8], self.sbox)

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


    def add_round_key(self, state, rkey):
        assert len(state) == 128
        assert len(rkey) == 128

        ret = []
        for i, b in enumerate(rkey):
            xored = self.do_xor([state[i], b])
            ret.append(xored)

        return ret

    def sub_bytes(self, state):
        assert len(state) == 128

        ret = []
        for i in range(16):
            ret.extend(self.sbox_clauses(state[i*8:(i+1)*8], self.sbox))

        return ret

    def flatten(self, input_array):
        result_array = []
        for element in input_array:
            if isinstance(element, int):
                result_array.append(element)
            elif isinstance(element, list):
                result_array += self.flatten(element)
        return result_array

    def shift_rows(self, state):
        assert len(state) == 128

        # making state2 into bytes
        state2 = []
        for i in range(16):
            state2.append(state[i*8:(i+1)*8])

        # run original algorithm to rotate
        rows = []
        for r in range(4):
            rows.append( state2[r::4] )
            rows[r] = rows[r][r:] + rows[r][:r]
        ret = [ r[c] for c in range(4) for r in rows ]
        assert len(ret) == 16

        ret_flat = self.flatten(ret)
        assert len(ret_flat) == 128
        return ret_flat

    def mix_columns(self, state):
        assert len(state) == 128

        ss = []
        # runs 4*(4 bytes) = 16 bytes = 128b state
        for c in range(4):
            col = []
            col_bytes = state[c*4*8:(c+1)*4*8]
            for i in range(4):
                col.append(col_bytes[i*8:(i+1)*8])

            tmp1 = self.sbox_clauses(col[0], self.sbox_gmul2)
            tmp2 = self.sbox_clauses(col[1], self.sbox_gmul3)
            ss.extend(self.do_xor_byte([tmp1, tmp2, col[2], col[3]]))

            tmp1 = self.sbox_clauses(col[1], self.sbox_gmul2)
            tmp2 = self.sbox_clauses(col[2], self.sbox_gmul3)
            ss.extend(self.do_xor_byte([col[0], tmp1, tmp2, col[3]]))

            tmp1 = self.sbox_clauses(col[2], self.sbox_gmul2)
            tmp2 = self.sbox_clauses(col[3], self.sbox_gmul3)
            ss.extend(self.do_xor_byte([col[0], col[1], tmp1, tmp2]))

            tmp1 = self.sbox_clauses(col[0], self.sbox_gmul3)
            tmp2 = self.sbox_clauses(col[3], self.sbox_gmul2)
            ss.extend(self.do_xor_byte([tmp1, col[1], col[2], tmp2]))

        assert len(ss) == 128
        return ss

    def cipher(self, ptext):
        #print "round[ 0].input: {0}".format(block.encode('hex'))
        state = list(ptext)
        keys = self.ks_expand()
        state = self.add_round_key(state, keys[0:128])
        for r in range(1, options.rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            k = keys[r*128:(r+1)*128]
            state = self.add_round_key(state, k)

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, keys[10*128:])
        #print "output: {0}".format(self.state.encode('hex'))
        return state


    def set_1b_cnf(self, v, value):
        assert type(v) == int

        if value:
            self.cnf.write("%d 0\n" % v)
        else:
            self.cnf.write("-%d 0\n" % v)

    def set_128b_cnf(self, vs, value):
        assert len(vs) == 128

        # add value to CNF for variables vs
        for i in range(128):
            val_bit = ((value[i//8])>>(i%8))&1
            self.set_1b_cnf(vs[i], val_bit)


def test_key_expansion(sbox):
    # generate random key
    key = []
    for i in range(16):
        byte = random.getrandbits(8)
        key.append(byte)
    print("Key is: ", key)

    # get correct expanded keystream from 2 different implementations
    norm = aesnormks.AESNormKS()
    good_exp_key = norm.ks_expand(key)
    print("Extended key is: ", good_exp_key)
    crypt = otheraes.AES_128()
    crypt.key = [chr(c) for c in key]
    plaintext = ['a']*16
    crypt.cipher(plaintext)
    check_keys = crypt.key_schedule()
    assert len(check_keys) == len(good_exp_key)
    for i in range(len(check_keys)):
        assert check_keys[i] == good_exp_key[i]
    print("AESNormKS vs otheraes.AES_128 test OK")

    # create aes.cnf to get extended key variables
    fname = "aes.cnf"
    aes = AESSAT(sbox, None, None, fname)
    expanded_key_vars = aes.ks_expand()
    #print("expanded_key_vars:", expanded_key_vars)
    assert len(expanded_key_vars) == 8*len(good_exp_key)

    # add key to CNF and get solution, i.e. extended key variable values
    aes.set_128b_cnf(aes.key, key)
    aes.cnf.close()
    solutions = get_n_sat_solutions(fname, 1)
    assert len(solutions) == 1
    solution = solutions[0]

    # check solution, i.e. extended key variable values in CNF against correct values
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


def test_aes(sbox, sbox_gmul2, sbox_gmul3):
    # generate random key
    key = []
    for i in range(16):
        byte = random.getrandbits(8)
        key.append(byte)
    print("Key is: ", key)


    # generate random ptext
    ptext = []
    for i in range(16):
        byte = random.getrandbits(8)
        ptext.append(byte)
    print("Ptext is: ", ptext)

    # set up and run normal AES
    crypt = otheraes.AES_128()
    crypt.key = [chr(c) for c in key]
    tmp_ptext = [chr(c) for c in ptext]
    ctext = crypt.cipher(tmp_ptext)
    print("ctext is: ", ctext)
    assert len(ctext) == 16 # returns 16 integers (all bytes)

    # initialize SAT engine
    fname = "aes.cnf"
    aes = AESSAT(sbox, sbox_gmul2, sbox_gmul3, fname)
    cnf_ciphertext = aes.cipher(aes.plaintext)

    # set values and solve
    aes.set_128b_cnf(aes.key, key)
    aes.set_128b_cnf(aes.plaintext, ptext)
    print("Key vars:" , aes.key)
    print("Plaintex vars: ", aes.plaintext)
    print("Ciphertext vars: ", cnf_ciphertext)
    aes.cnf.close()
    solutions = get_n_sat_solutions(fname, 1)
    assert len(solutions) == 1
    solution = solutions[0]

    # check solution, i.e. ciphertext
    for i in range(128):
        v = cnf_ciphertext[i]
        value = solution[v]

        good_value = (ctext[i//8]>>(i%8))&1
        #print("value     :", value)
        #print("good value:", good_value)
        if good_value != value:
            print("At bit: %d incorrect value" % i)
        assert good_value == value

    print("Test OK")


def generate_problem(key_bits, fname, sbox, sbox_gmul2, sbox_gmul3):
    # generate random key
    key = []
    for i in range(16):
        byte = random.getrandbits(8)
        key.append(byte)
    print("Key is: ", key)


    # generate random ptext
    ptext = []
    for i in range(16):
        byte = random.getrandbits(8)
        ptext.append(byte)
    print("Ptext is: ", ptext)

    # set up and run normal AES
    crypt = otheraes.AES_128()
    crypt.key = [chr(c) for c in key]
    tmp_ptext = [chr(c) for c in ptext]
    ctext = crypt.cipher(tmp_ptext)
    print("ctext is: ", ctext)
    assert len(ctext) == 16 # returns 16 integers (all bytes)

    # initialize SAT engine
    aes = AESSAT(sbox, sbox_gmul2, sbox_gmul3, fname)
    cnf_ciphertext = aes.cipher(aes.plaintext)

    # set guessed key values
    myvars = list(aes.key)
    random.shuffle(myvars)
    myvars = myvars[:key_bits]
    myvars_val = []
    for v in myvars:
        if not options.satisfiable:
            val = random.randint(0, 1)
        else:
            bit = v-1 # NOTE: relies on key being 1...129 of self.v's
            val = (key[bit//8]>>(bit%8)) & 1
        myvars_val.append(val)
        aes.set_1b_cnf(v, val)

    # set plaintext
    aes.set_128b_cnf(aes.plaintext, ptext)

    #set ciphertext
    for i in range(128):
        v = cnf_ciphertext[i]
        ctext_bit = (ctext[i//8]>>(i%8))&1
        aes.set_1b_cnf(v, ctext_bit)

    # solve
    print("Key vars set:" , myvars)
    print("Key vars set to: ", myvars_val)
    assert len(myvars) == key_bits
    assert len(myvars_val) == key_bits

    print("Plaintex: ", ptext)
    print("Ciphertext: ", ctext)
    aes.cnf.close()
    #solutions = get_n_sat_solutions(fname, 1)
    #print("Solutions: ", len(solutions))


class PlainHelpFormatter(optparse.IndentedHelpFormatter):

    def format_description(self, description):
        if description:
            return description + "\n"
        else:
            return ""

if __name__ == "__main__":
    usage = usage = "usage: %prog [options] KEYBITS FILE"
    desc = """Generate AES cipher with K randomly picked, randomly set keys, and a valid plaintext and ciphertext combination, given a randomly picked key and plaintext."""
    parser = optparse.OptionParser(usage=usage, description=desc,
                                   formatter=PlainHelpFormatter())

    parser.add_option("--verbose", "-v", action="store_true", default=False,
                      dest="verbose", help="Print more output")
    parser.add_option("--sboxtest", action="store_true", default=False,
                      dest="sbox_test", help="Test sboxes and exit")
    parser.add_option("--gensboxes", action="store_true", default=False,
                      dest="gen_sboxes", help="Generate S-boxes. If not set, pickled sboxes must be present.")
    parser.add_option("--keyexptest", action="store_true", default=False,
                      dest="key_expansion_test", help="Test key expansion")
    parser.add_option("--aestest", action="store_true", default=False,
                      dest="aes_test", help="Test the full AES by giving valid key+plaintext and checking ciphertext")
    parser.add_option("--seed", dest="seed",
                      help="Seed for generating keys bits, vars to give, etc.",
                      type=int)
    parser.add_option("--sat", action="store_true", default=False,
                      dest="satisfiable", help="Make the problem SAT by giving the correct key bit values")
    parser.add_option("--rounds", type=int, default=10,
                      dest="rounds", help="Number of rounds to run AES")
    parser.add_option("--printsboxes", action="store_true", default=False,
                      dest="print_sboxes", help="Print sboxes and exit")
    parser.add_option("--printgmul", action="store_true", default=False,
                      dest="print_gmul", help="Print column multiplication via gmul and exit")
    (options, args) = parser.parse_args()

    if options.sbox_test:
        sboxgen = SBoxGen()
        sboxgen.test()
        exit(0)

    if options.gen_sboxes:
        random.seed(40)
        sboxgen = SBoxGen()
        sbox = sboxgen.create_sboxes(sboxgen.sbox_orig)
        sbox_gmul2 = sboxgen.create_sboxes(sboxgen.Gmul[0x02])
        sbox_gmul3 = sboxgen.create_sboxes(sboxgen.Gmul[0x03])
        with open("sbox.pickle", "wb") as f:
            pickle.dump(sbox, f)

        with open("sbox_gmul2.pickle", "wb") as f:
            pickle.dump(sbox_gmul2, f)

        with open("sbox_gmul3.pickle", "wb") as f:
            pickle.dump(sbox_gmul3, f)

        print("Generated s-box pickle files")
        exit(0)
    else:
        with open("sbox.pickle", "rb") as f:
            sbox = pickle.load(f)

        with open("sbox_gmul2.pickle", "rb") as f:
            sbox_gmul2 = pickle.load(f)

        with open("sbox_gmul3.pickle", "rb") as f:
            sbox_gmul3 = pickle.load(f)

    if options.print_sboxes:
        for i in range(8):
            print("sbox ", i)
            for cl in sbox[i]:
                print(cl)
        exit(0)

    if options.print_gmul:
        for i in range(8):
            print("sbox ", i)
            for cl in sbox_gmul2[i]:
                print(cl)
        exit(0)

    if options.key_expansion_test:
        for test_no in range(20):
            test_key_expansion(sbox)
        exit(0)

    if options.aes_test:
        for i in range(20):
            test_aes(sbox, sbox_gmul2, sbox_gmul3)
        exit(0)

    if len(args) < 2:
        print("ERROR! Must pass [number of key bits] and [filename] to generate AES problem into")
        exit(-1)

    if len(args) > 2:
        print("ERROR! You gave too many positional options. You must give exactly 2!")
        exit(-1)

    key_bits = int(args[0])
    fname = str(args[1])

    print("Giving %d key bits, putting into file '%s'" % (key_bits, fname))
    random.seed(options.seed)
    generate_problem(key_bits, fname, sbox, sbox_gmul2, sbox_gmul3)
    print("AES generated with random %d key bits set randomly with a randomly picked plaintext, and a correct ciphertext for a randomly generated key is in file '%s'" % (key_bits, fname))


















