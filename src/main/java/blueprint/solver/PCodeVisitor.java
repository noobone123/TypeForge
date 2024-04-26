package blueprint.solver;

import blueprint.utils.DecompilerHelper;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;

import static blueprint.utils.DecompilerHelper.getSigned;

public class PCodeVisitor {

    /**
     * VarNode with data-flow traceable to original pointer.
     * For example, If there is a statement like following:
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

        @Override
        public String toString() {
            return "PointerRef{" +
                    "varnode=" + varnode +
                    ", offset=" + Long.toHexString(offset) +
                    '}';
        }
    }

    public Context ctx;
    public HashSet<Varnode> visited;
    public LinkedList<PointerRef> workList;
    public HighVariable root = null;

    public PCodeVisitor(Context ctx) {
        this.ctx = ctx;
        visited = new HashSet<>();
        workList = new LinkedList<>();
    }

    /**
     * Start visiting the HighVariable
     * @param currentVar the current HighVariable to visit
     */
    public void run(HighVariable currentVar) {
        root = currentVar;
        assert workList.isEmpty();

        // add the root's instances to the todoList, because a HighVariable may reside
        // in different places at various times in the program
        for (var varnode : root.getInstances()) {
            workList.add(new PointerRef(varnode, 0));
        }

        Logging.debug("Visiting HighVariable: " + root.getName());

        while (!workList.isEmpty()) {
            PointerRef cur = workList.remove(0);
            Logging.debug(String.format(
                    "[Varnode] Current varnodeAST-%d %s with offset 0x%x to worklist",
                    ((VarnodeAST)cur.varnode).getUniqueId(), cur.varnode, cur.offset));

            if (cur.varnode == null) {
                continue;
            }

            Iterator<PcodeOp> desc = cur.varnode.getDescendants();
            while (desc.hasNext()) {
                PcodeOp pcodeOp = desc.next();
                Logging.debug("PCodeOp: " + pcodeOp.toString());

                switch (pcodeOp.getOpcode()) {
                    case PcodeOp.INT_ADD:
                    case PcodeOp.INT_SUB:
                        handleAddOrSub(cur, pcodeOp);
                        break;
                    case PcodeOp.CAST:
                        handleCast(cur, pcodeOp);
                        break;
                    case PcodeOp.COPY:
                        handleCopy(cur, pcodeOp);
                        break;
                    case PcodeOp.MULTIEQUAL:
                        handleMultiEqual(cur, pcodeOp);
                        break;
                    case PcodeOp.LOAD:
                        handleLoad(cur, pcodeOp);
                        break;
                    case PcodeOp.STORE:
                        handleStore(cur, pcodeOp);
                        break;
                    case PcodeOp.PTRADD:
                        handlePtrAdd(cur, pcodeOp);
                        break;
                    case PcodeOp.PTRSUB:
                        handlePtrSub(cur, pcodeOp);
                        break;
                }

            }


        }

    }


    /**
     * If parameter is an ADD or SUB operation, we can calculate the new offset
     * But remember, only varnode_1 = varnode_0 + const is not enough to prove that
     * varnode_0 is a base address of structure.
     * For example:
     * b = a + 4 is just a simple arithmetic operation, it does not mean that `a` is a base address of a structure.
     * But if there is a load/store operation like:
     * c = *(a + 4) or *(a + 4) = c, then we can say that `a` is a base address of a structure.
     * @param cur the current PointerRef
     * @param pcodeOp the PCodeOp
     */
    private void handleAddOrSub(PointerRef cur, PcodeOp pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        Varnode output = pcodeOp.getOutput();
        long newOff;
        if (!inputs[1].isConstant()) {
            return;
        }
        newOff = cur.offset +
            (pcodeOp.getOpcode() == PcodeOp.INT_ADD ? getSigned(inputs[1]) : -getSigned(inputs[1]));

        if (!OffsetSanityCheck(newOff)) {
            return;
        }

        updateWorkList(output, newOff);
    }


    private void handleCopy(PointerRef cur, PcodeOp pcodeOp) {
        Varnode output = pcodeOp.getOutput();
        var inputSymbol = pcodeOp.getInput(0).getHigh().getSymbol();
        var outputSymbol = output.getHigh().getSymbol();

        // TODO: restrict the aliasing to only pointer Type?
        if (ctx.setAliasIntra(inputSymbol, outputSymbol)) {
            Logging.debug(
                    String.format("[Align] Aligning dataflow facts from %s to %s",
                            inputSymbol.getName(), outputSymbol.getName())
                );
        }

        updateWorkList(output, cur.offset);
    }


    private void handleCast(PointerRef cur, PcodeOp pcodeOp) {
        Varnode output = pcodeOp.getOutput();
        updateWorkList(output, cur.offset);
    }


    private void handleMultiEqual(PointerRef cur, PcodeOp pcodeOp) {
        // TODO: Merging multiple dataflow facts from multiple varnodes?
        Varnode output = pcodeOp.getOutput();
        updateWorkList(output, cur.offset);
    }


    /**
     * If pcodeOp is a LOAD or STORE operation, it's possible that the offset is a field of a structure.
     * For instance:
     * <p>
     *     <code> varnode_1 = *(varnode_0 + 4) </code>
     *     <code> *(varnode_1 + 4) = varnode_2 </code>
     * </p>
     * And type of this field is determined by the type of loaded/stored varnode's type.
     * However, be aware that some case might be loaded/store into a context even if they aren't
     * fields of a structure.
     * For instance:
     * <p>
     *     <code> varnode_1 = *varnode_0 </code>
     *     <code> *varnode_1 = varnode_2 </code>
     * </p>
     * Such cases can be excluded in later stages.
     * @param cur The current PointerRef
     * @param pcodeOp The PCodeOp
     */
    private void handleLoad(PointerRef cur, PcodeOp pcodeOp) {
        Varnode output = pcodeOp.getOutput();

        // The amount of data loaded by this instruction is determined by the size of the output variable
        DataType outDT = DecompilerHelper.getDataTypeTraceForward(output);

        ctx.addField(root.getSymbol(), cur.offset, outDT);
        Logging.collectTypeLog(root, cur.offset, outDT);
    }

    /**
     * Same as handleLoad, but for STORE operation
     */
    private void handleStore(PointerRef cur, PcodeOp pcodeOp) {
        // the slot index of cur.varnode is 1, which means that this varnode
        // represent the memory location to be stored
        if (pcodeOp.getSlot(cur.varnode) != 1) {
            return;
        }
        var storedValue = pcodeOp.getInput(2);
        var storedValueDT = DecompilerHelper.getDataTypeTraceBackward(storedValue);

        ctx.addField(root.getSymbol(), cur.offset, storedValueDT);
        Logging.collectTypeLog(root, cur.offset, storedValueDT);
    }

    /**
     * Handle PTRADD operation. In PTRADD operation,
     * output = input0 + input1 * input2, where input0 is array's base address, input1 is index
     * and input2 is element size.
     * @param cur The current PointerRef
     * @param pcodeOp The PCodeOp
     */
    private void handlePtrAdd(PointerRef cur, PcodeOp pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        if (!inputs[1].isConstant() || !inputs[2].isConstant()) {
            return;
        }
        var newOff = cur.offset + getSigned(inputs[1]) * getSigned(inputs[2]);
        if (OffsetSanityCheck(newOff)) {
            updateWorkList(pcodeOp.getOutput(), newOff);
        }
    }

    /**
     * A PTRSUB performs the simple pointer calculation, input0 + input1
     * Input0 is a pointer to the beginning of the structure, and input1 is a byte offset to the subcomponent.
     * As an operation, PTRSUB produces a pointer to the subcomponent and stores it in output.
     * @param cur The current PointerRef
     * @param pcodeOp The PCodeOp
     */
    private void handlePtrSub(PointerRef cur, PcodeOp pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        if (!inputs[1].isConstant()) {
            return;
        }
        var newOff = cur.offset + getSigned(inputs[1]);
        if (OffsetSanityCheck(newOff)) {
            updateWorkList(pcodeOp.getOutput(), newOff);
        }
    }


    /**
     * Update worklist.
     * Be careful, some varnode looks identical, but actually they have different uniqueId.
     * So they are different varnodes.
     * @param output the output varnode which is going to be added to worklist
     * @param offset the offset of the output varnode
     */
    private void updateWorkList(Varnode output, long offset) {
        if (!(output instanceof VarnodeAST ast)) {
            Logging.warn("Varnode is not VarnodeAST: " + output.toString());
            return;
        }
        if (visited.contains(output)) {
            return;
        }
        workList.add(new PointerRef(output, offset));
        Logging.debug(String.format(
                "[WorkList] Adding varnodeAST-%d %s with offset 0x%x to worklist",
                ast.getUniqueId(), ast, offset));

        visited.add(output);
    }


    /**
     * Check if the offset is sane to be a structure offset
     * @param offset the offset
     * @return true if the offset is sane
     */
    private boolean OffsetSanityCheck(long offset) {
        if (offset < 0) {
            return false;
        }
        // TODO: 0x2000 is a reasonable limit for a structure ?
        else return offset <= 0x2000;
    }

}
