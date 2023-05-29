#!/usr/bin/env python3

import logging
import ot
import util
import yao
from abc import ABC, abstractmethod

logging.basicConfig(format="[%(levelname)s] %(message)s",
                    level=logging.WARNING)

class YaoGarbler(ABC):
    """An abstract class for Yao garblers"""
    def __init__(self, circuits):
        circuits = util.parse_json(circuits)
        self.name = circuits["name"]
        self.circuits = []

        for circuit in circuits["circuits"]:
            garbled_circuit = yao.GarbledCircuit(circuit)
            pbits = garbled_circuit.get_pbits()
            entry = {
                "circuit": circuit,
                "garbled_circuit": garbled_circuit,
                "garbled_tables": garbled_circuit.get_garbled_tables(),
                "keys": garbled_circuit.get_keys(),
                "pbits": pbits,
                "pbits_out": {w: pbits[w]
                              for w in circuit["out"]},
            }
            self.circuits.append(entry)

    @abstractmethod
    def start(self):
        pass

def check_input(input:str):

    # This function is used for check the input of Alice and Bob.
    # The correct format of the input is [d,d,d,d] where d are digits (0 or 1)
    #
    # The input is a string, the output is True if the input's format is correct, False otherwise

    if (len(input) != 9):
        return False

    elif (((input[1] != "0") and (input[1] != "1")) or ((input[3] != "0") and (input[3] != "1")) or
        ((input[5] != "0") and (input[5] != "1")) or ((input[7] != "0") and (input[7] != "1"))):
        return False

    elif (input[0] != "[") or (input[8] != "]"):
        return False

    elif (input[2] != ",") or (input[4] != ",") or (input[6] != ","):
        return False

    else:
        return True

def clean_string(a:str):
    # This function is used for clean the string
    # Examples:   [1,1,1,1] ---> 1111
    #             [1,0,1,0] ---> 1010
    #             1 1 1 1 ---> 1111
    #             1 0 1 0 ---> 1010
    if (a == ""):
        return a
    elif a[0] == "[":
        return a.replace(',', '').replace('[', '').replace(']', '')
    else:
        return a.replace(' ', '')

class Alice(YaoGarbler):
    """Alice is the creator of the Yao circuit.

    Alice creates a Yao circuit and sends it to the evaluator along with her
    encrypted inputs.

    Attributes:
        circuits: the JSON file containing circuits
        oblivious_transfer: Optional; enable the Oblivious Transfer protocol
            (True by default).
    """
    def __init__(self, circuits, oblivious_transfer=True):
        super().__init__(circuits)
        self.socket = util.GarblerSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)

    def start(self):
        """Start Yao protocol."""
        for circuit in self.circuits:
            to_send = {
                "circuit": circuit["circuit"],
                "garbled_tables": circuit["garbled_tables"],
                "pbits_out": circuit["pbits_out"],
            }
            logging.debug(f"Sending {circuit['circuit']['id']}")
            self.socket.send_wait(to_send)
            self.print(circuit)

    def print(self, entry):
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_keys = {  # map from Bob's wires to a pair (key, encr_bit)
            w: self._get_encr_bits(pbits[w], key0, key1)
            for w, (key0, key1) in keys.items() if w in b_wires
        }

        print(f"======== {circuit['id']} ========")

        #The following part of the code allows you to insert Alice's input
        while True:
            input_set: list = []
            while (input_set == [] or (input_set[-1] != "end" and input_set[-1] != "q" )):
                candidate = input("\nYou can write the Alice's set \n"
                                  "or you can write 'end' to indicate the end of the set \n"
                                  "or you can write 'q' for conclude: ")

                if (candidate == "q" or candidate == "end"):
                    input_set = input_set + [candidate]
                elif check_input(candidate):
                    input_set = input_set + [candidate]
                    print("\nThe current set of Alice is: ",input_set)
                else:
                    print("\nThere is a mistake, rewrite the input, Alice's input must be of the type [d,d,d,d]")

            if (input_set[-1] == "q"):
                print("\nThe Yao protocol has ended, now i check the results")
                break

            if (input_set[-1] == "end" and len(input_set) == 1):
                print("\nIt is impossible calcuate the max of the empty set")
                break

            input_set_copy: list = []
            for i in range(len(input_set) - 1):
                input_set_copy = input_set_copy + [int(clean_string(input_set[i]), 2)]

            input_a = input_set[input_set_copy.index(max(input_set_copy))]
            print("\nAlice's maximum value is: ", input_a)

            input_set.clear()

            bits_a = input_a[1:len(input_a) - 1].replace(',', '')
            bits_a = list([int(c) for c in bits_a])

            # Map Alice's wires to (key, encr_bit)
            for i in range(len(a_wires)):
                a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]],
                                        pbits[a_wires[i]] ^ bits_a[i])

            # Send Alice's encrypted inputs and keys to Bob
            result = self.ot.get_result(a_inputs, b_keys)

            # Format output
            str_bits_a = input_a
            str_result = ' '.join([str(result[w]) for w in outputs])

            print(f"  Alice{a_wires} = {str_bits_a} "
                  f"Outputs{outputs} = {str_result}")

            # I write the Alice's input in alice_input.txt
            # This file will be used at the end to see if the result has been calculated correctly
            alice_file = open("alice_input.txt", "a")
            alice_file.write(input_a + "\n")
            alice_file.close()

        print()

    def _get_encr_bits(self, pbit, key0, key1):
        return ((key0, 0 ^ pbit), (key1, 1 ^ pbit))

class Bob:
    """Bob is the receiver and evaluator of the Yao circuit.

    Bob receives the Yao circuit from Alice, computes the results and sends
    them back.

    Args:
        oblivious_transfer: Optional; enable the Oblivious Transfer protocol
            (True by default).
    """
    def __init__(self, oblivious_transfer=True):
        self.socket = util.EvaluatorSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)

    def listen(self):
        """Start listening for Alice messages."""
        logging.info("Start listening")
        try:
            for entry in self.socket.poll_socket():
                self.socket.send(True)
                self.send_evaluation(entry)
        except KeyboardInterrupt:
            logging.info("Stop listening")

    def send_evaluation(self, entry):
        """Evaluate yao circuit for all Bob and Alice's inputs and
        send back the results.

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        circuit, pbits_out = entry["circuit"], entry["pbits_out"]
        garbled_tables = entry["garbled_tables"]
        a_wires = circuit.get("alice", [])  # list of Alice's wires
        b_wires = circuit.get("bob", [])  # list of Bob's wires
        outputs = circuit["out"]

        # The following part of the code allows you to insert Bob's input
        while True:
            print(f"Received {circuit['id']}")

            input_set: list = []
            while (input_set == [] or (input_set[-1] != "end" and input_set[-1] != "q")):
                candidate = input("\nYou can write the Bob's set \n"
                                  "or you can write 'end' to indicate the end of the set \n"
                                  "or you can write 'q' for conclude: ")

                if (candidate == "q" or candidate == "end"):
                    input_set = input_set + [candidate]

                elif check_input(candidate):
                    input_set = input_set + [candidate]
                    print("\nThe current set of Bob is: ",input_set)

                else:
                    print("\nThere is a mistake, rewrite the input, Bob's input must be of the type [d,d,d,d]")

            if (input_set[-1] == "q"):

                print("\nThe Yao protocol has ended, now i check the results")
                self.socket.close()
                break

            if (input_set[-1] == "end" and len(input_set) == 1):

                self.socket.close()
                print("\nIt is impossible calcuate the max of the empty set")
                break

            input_set_copy: list = []
            for i in range(len(input_set) - 1):
                input_set_copy = input_set_copy + [int(clean_string(input_set[i]), 2)]

            input_b = input_set[input_set_copy.index(max(input_set_copy))]
            print("\nBob's maximum value is: ", input_b)

            input_set.clear()

            bits_b = input_b[1:len(input_b) - 1].replace(',', '')
            bits_b = [int(c) for c in bits_b]

            # Create dict mapping each wire of Bob to Bob's input
            b_inputs_clear = {
                b_wires[i]: bits_b[i]
                for i in range(len(b_wires))
            }

            # Evaluate and send result to Alice
            result = self.ot.send_result(circuit, garbled_tables, pbits_out,
                                                             b_inputs_clear)

            # Format output
            str_bits_b = input_b
            str_result = ' '.join([str(result[w]) for w in outputs])

            print(f"  Bob{a_wires} = {str_bits_b} "
                  f"Outputs{outputs} = {str_result}")

            # I write the Bob's output in bob_output.txt
            # This file will be used at the end to see if the result has been calculated correctly
            output_file = open("output_function.txt", "a")
            output_file.write(str_result + "\n")
            output_file.close()

            # I write the Bob's input in alice_input.txt
            # This file will be used at the end to see if the result has been calculated correctly
            bob_file = open("bob_input.txt", "a")
            bob_file.write(input_b + "\n")
            bob_file.close()

class LocalTest(YaoGarbler):
    """A class for local tests.

    Print a circuit evaluation or garbled tables.

    Args:
        circuits: the JSON file containing circuits
        print_mode: Print a clear version of the garbled tables or
            the circuit evaluation (the default).
    """
    def __init__(self, circuits, print_mode="circuit"):
        super().__init__(circuits)
        self._print_mode = print_mode
        self.modes = {
            "circuit": self._print_evaluation,
            "table": self._print_tables,
        }
        logging.info(f"Print mode: {print_mode}")

    def start(self):
        """Start local Yao protocol."""
        for circuit in self.circuits:
            self.modes[self.print_mode](circuit)

    def _print_tables(self, entry):
        """Print garbled tables."""
        entry["garbled_circuit"].print_garbled_tables()

    def _print_evaluation(self, entry):
        """Print circuit evaluation."""
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        garbled_tables = entry["garbled_tables"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_inputs = {}  # map from Bob's wires to (key, encr_bit) inputs
        pbits_out = {w: pbits[w] for w in outputs}  # p-bits of outputs
        N = len(a_wires) + len(b_wires)

        print(f"======== {circuit['id']} ========")

        # Generate all possible inputs for both Alice and Bob
        for bits in [format(n, 'b').zfill(N) for n in range(2**N)]:
            bits_a = [int(b) for b in bits[:len(a_wires)]]  # Alice's inputs
            bits_b = [int(b) for b in bits[N - len(b_wires):]]  # Bob's inputs

            # Map Alice's wires to (key, encr_bit)
            for i in range(len(a_wires)):
                a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]],
                                        pbits[a_wires[i]] ^ bits_a[i])

            # Map Bob's wires to (key, encr_bit)
            for i in range(len(b_wires)):
                b_inputs[b_wires[i]] = (keys[b_wires[i]][bits_b[i]],
                                        pbits[b_wires[i]] ^ bits_b[i])

            result = yao.evaluate(circuit, garbled_tables, pbits_out, a_inputs,
                                  b_inputs)

            # Format output
            str_bits_a = ' '.join(bits[:len(a_wires)])
            str_bits_b = ' '.join(bits[len(a_wires):])
            str_result = ' '.join([str(result[w]) for w in outputs])

            print(f"  Alice{a_wires} = {str_bits_a} "
                  f"Bob{b_wires} = {str_bits_b}  "
                  f"Outputs{outputs} = {str_result}")

        print()

    @property
    def print_mode(self):
        return self._print_mode

    @print_mode.setter
    def print_mode(self, print_mode):
        if print_mode not in self.modes:
            logging.error(f"Unknown print mode '{print_mode}', "
                          f"must be in {list(self.modes.keys())}")
            return
        self._print_mode = print_mode

def main(
    party,
    circuit_path="circuits/default.json",
    oblivious_transfer=True,
    print_mode="circuit",
    loglevel=logging.WARNING,
):
    logging.getLogger().setLevel(loglevel)

    if party == "alice":
        alice = Alice(circuit_path, oblivious_transfer=oblivious_transfer)
        alice.start()
    elif party == "bob":
        bob = Bob(oblivious_transfer=oblivious_transfer)
        bob.listen()
    elif party == "local":
        local = LocalTest(circuit_path, print_mode=print_mode)
        local.start()
    else:
        logging.error(f"Unknown party '{party}'")

if __name__ == '__main__':
    import argparse

    def init():
        loglevels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }

        parser = argparse.ArgumentParser(description="Run Yao protocol.")
        parser.add_argument("party",
                            choices=["alice", "bob", "local"],
                            help="the yao party to run")
        parser.add_argument(
            "-c",
            "--circuit",
            metavar="circuit.json",
            default="circuits/default.json",
            help=("the JSON circuit file for alice and local tests"),
        )
        parser.add_argument("--no-oblivious-transfer",
                            action="store_true",
                            help="disable oblivious transfer")
        parser.add_argument(
            "-m",
            metavar="mode",
            choices=["circuit", "table"],
            default="circuit",
            help="the print mode for local tests (default 'circuit')")
        parser.add_argument("-l",
                            "--loglevel",
                            metavar="level",
                            choices=loglevels.keys(),
                            default="warning",
                            help="the log level (default 'warning')")

        main(
            party=parser.parse_args().party,
            circuit_path=parser.parse_args().circuit,
            oblivious_transfer=not parser.parse_args().no_oblivious_transfer,
            print_mode=parser.parse_args().m,
            loglevel=loglevels[parser.parse_args().loglevel],
        )

    init()

    def verfiy_output(a_in, b_in, out):
        # This function is used for check the final results.

        input_alice = open(a_in, "r")
        input_bob = open(b_in, "r")
        out_max = open(out, "r")

        while True:

            a = clean_string(input_alice.readline())
            b = clean_string(input_bob.readline())
            o = clean_string(out_max.readline())

            if a == "":
                break

            a = int(a, 2)
            b = int(b, 2)
            o = int(o, 2)

            if (a > b) and (o == a):
                real_result = "CORRECT"

            elif (a < b) and (o == b):
                real_result = "CORRECT"

            elif (a == b) and (o == b):
                real_result = "CORRECT"

            else:
                real_result = "INCORRECT"

            print("alice value is:", a, "/", "bob bob value is: ", b, "/", "output value is: ", o, "/",
                  "the predict result is", real_result)

        # Now, I can close the files
        input_alice.close()
        input_bob.close()
        out_max.close()



    verfiy_output("alice_input.txt", "bob_input.txt", "output_function.txt")


