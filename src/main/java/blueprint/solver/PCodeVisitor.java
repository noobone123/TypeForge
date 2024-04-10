package blueprint.solver;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import groovy.util.logging.Log;

import java.util.HashMap;
import java.util.Iterator;

public class PCodeVisitor {

    public Varnode root;
    public Context ctx;

    public PCodeVisitor(Varnode root, Context ctx) {
        this.root = root;
        this.ctx = ctx;
    }

    public void run() {
        // Returns: iterator to all PcodeOp s that take this as input
        Iterator<PcodeOp> descendants = root.getDescendants();
        while (descendants.hasNext()) {
            PcodeOp pcodeOp = descendants.next();
            Varnode output = pcodeOp.getOutput();
            Varnode[] inputs = pcodeOp.getInputs();
            var opcode = pcodeOp.getOpcode();

            Logging.info("Desc PcodeOp: " + pcodeOp);
            Logging.info("Output: " + output);
            Logging.info("Inputs: ");
            for (var input : inputs) {
                Logging.info("\t" + input.toString());
            }
            Logging.info("Opcode: " + opcode);

            switch (opcode) {
                case PcodeOp.INT_SUB:
                case PcodeOp.INT_ADD:
                    Logging.info("Found an addition or subtraction operation");
            }

        }

    }


    private void handleAddOrSub(Varnode output, Varnode[] inputs) {
        // Do something with the addition or subtraction operation
    }
}
