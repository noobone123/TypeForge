package blueprint.solver;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import groovy.util.logging.Log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

public class PCodeVisitor {

    /**
     * VarNode with data-flow traceable to original pointer.
     * For example, If there is an statement like following:
     * <p>
     *     <code> varnode_1 = *(varnode_0 + 4) </code>
     *     <code> varnode_2 = *(varnode_1 + 4) </code>
     * </p>
     *
     * varnode_0 is the original pointer, varnode_1's offset is 4, varnode_2's offset is 8
     */
    public static class PointerRef {
        Varnode varnode;		// The traced Varnode
        long offset;			// Offset relative to ** Original ** pointer

        public PointerRef(Varnode ref, long off) {
            varnode = ref;
            offset = off;
        }
    }

    public HighVariable root;
    public Context ctx;
    public ArrayList<PointerRef> todoList;
    public HashSet<Varnode> doneList;

    public PCodeVisitor(HighVariable highVar, Context ctx) {
        this.root = highVar;
        this.ctx = ctx;

        todoList = new ArrayList<>();
        doneList = new HashSet<>();

        todoList.add(new PointerRef(root.getRepresentative(), 0));

        Logging.info("Visiting HighVariable: " + root.getName());

        // TODO: should we add the root's instances to the todoList?
    }


    public void run() {

        while (!todoList.isEmpty()) {
            PointerRef cur = todoList.remove(0);
            Logging.info("Current Varnode: " + cur.varnode.toString() + " Offset: " + cur.offset);
            if (cur.varnode == null) {
                continue;
            }

            Iterator<PcodeOp> desc = cur.varnode.getDescendants();
            while (desc.hasNext()) {
                PcodeOp pcodeOp = desc.next();
                Varnode output = pcodeOp.getOutput();
                Varnode[] inputs = pcodeOp.getInputs();

                Logging.info("PCodeOp: " + pcodeOp.toString());

                switch (pcodeOp.getOpcode()) {
                    case PcodeOp.INT_ADD:
                    case PcodeOp.INT_SUB:
                        handleAddOrSub(output, inputs);
                        break;
                }

            }


        }

    }


    private void handleAddOrSub(Varnode output, Varnode[] inputs) {
        // Do something with the addition or subtraction operation
    }
}
