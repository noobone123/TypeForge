package blueprint.solver;

import blueprint.utils.DecompilerHelper;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;
import groovy.util.logging.Log;

import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

import static blueprint.utils.DecompilerHelper.getSigned;

public class PCodeVisitor {

    /**
     * VarNode with data-flow traceable to base pointer.
     * For example, If there is a statement like following:
     * <p>
     *     <code> varnode_1 = *(varnode_0 + 4) </code>
     *     <code> varnode_2 = *(varnode_1 + 4) </code>
     * </p>
     *
     * varnode_0 is the original pointer, varnode_1's offset is 4, varnode_2's offset is 8
     */
    public static class PointerRef {
        Varnode base;           // The base pointer
        Varnode current;		// The current pointer
        long offset;			// Offset relative to ** Base ** pointer

        public PointerRef(Varnode base, Varnode ref, long off) {
            this.base = base;
            current = ref;
            offset = off;
        }

        @Override
        public String toString() {
            var currentAST = (VarnodeAST) current;
            var baseAST = (VarnodeAST) base;
            return "PointerRef{ " +
                    "curr = " + currentAST.getUniqueId() + "_" + currentAST +  ", " +
                    "base = " + baseAST.getUniqueId() + "_" + baseAST + ", " +
                    "offset = 0x" + Long.toHexString(offset) +
                    " }";
        }
    }

    public Context ctx;
    public HashSet<String> collectedPtrRef;
    public LinkedList<PointerRef> workList;
    public HighVariable root = null;

    public PCodeVisitor(Context ctx) {
        this.ctx = ctx;
        collectedPtrRef = new HashSet<>();
        workList = new LinkedList<>();
    }

    /**
     * Start visiting the HighVariable
     * @param currentVar the current HighVariable to visit
     */
    public void run(HighVariable currentVar) {
        root = currentVar;
        assert workList.isEmpty();

        // TODO: How to handle Loop ?

        while (!workList.isEmpty()) {
            PointerRef cur = workList.remove(0);
            Logging.debug("[PtrRef] Current Ref " + cur);

            if (cur.current == null) {
                continue;
            }

            Iterator<PcodeOp> desc = cur.current.getDescendants();
            while (desc.hasNext()) {
                PcodeOp pcodeOp = desc.next();

                switch (pcodeOp.getOpcode()) {
                    case PcodeOp.INT_ADD:
                    case PcodeOp.INT_SUB:
                        Logging.debug("[PCodeOp] " + pcodeOp);
                        handleAddOrSub(cur, pcodeOp);
                        break;
                    case PcodeOp.CAST:
                        Logging.debug("[PCodeOp] " + pcodeOp);
                        handleCast(cur, pcodeOp);
                        break;
                    case PcodeOp.COPY:
                        Logging.debug("[PCodeOp] " + pcodeOp);
                        handleCopy(cur, pcodeOp);
                        break;
                    case PcodeOp.MULTIEQUAL:
                        Logging.debug("[PCodeOp] " + pcodeOp);
                        handleMultiEqual(cur, pcodeOp);
                        break;
                    case PcodeOp.LOAD:
                        Logging.debug("[PCodeOp] " + pcodeOp);
                        handleLoad(cur, pcodeOp);
                        break;
                    case PcodeOp.STORE:
                        Logging.debug("[PCodeOp] " + pcodeOp);
                        handleStore(cur, pcodeOp);
                        break;
                    case PcodeOp.PTRADD:
                        Logging.debug("[PCodeOp] " + pcodeOp);
                        handlePtrAdd(cur, pcodeOp);
                        break;
                    case PcodeOp.PTRSUB:
                        Logging.debug("[PCodeOp] " + pcodeOp);
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

        updateWorkList(output, cur.base, newOff);
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

        updateWorkList(output, cur.base, cur.offset);
    }


    private void handleCast(PointerRef cur, PcodeOp pcodeOp) {
        Varnode output = pcodeOp.getOutput();
        updateWorkList(output, cur.base, cur.offset);
    }


    private void handleMultiEqual(PointerRef cur, PcodeOp pcodeOp) {
        // TODO: Merging multiple dataflow facts from multiple varnodes?
        Varnode output = pcodeOp.getOutput();
        updateWorkList(output, cur.base, cur.offset);
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
        if (pcodeOp.getSlot(cur.current) != 1) {
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
            updateWorkList(pcodeOp.getOutput(), cur.base, newOff);
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
            updateWorkList(pcodeOp.getOutput(), cur.base, newOff);
        }
    }


    /**
     * Find all varnode instances of new root (HighVariable) and add them to the worklist
     * A new root is a parameter, argument, return value or their alias in most cases.
     * @param hVar the new HighVariable to add
     */
    private void addAllInstanceToWorkList(HighVariable hVar) {
        assert hVar.getSymbol() != null; // Make sure the new root has a corresponding HighSymbol
        var startVN = hVar.getRepresentative();
        var ptrRef = new PointerRef(startVN, startVN, 0);
        workList.add(ptrRef);
        Logging.debug("[WorkList] Adding " + ptrRef);

        // Add the root's instances to the todoList, because a HighVariable may reside
        // in different places at various times in the program
        for (var varnode : hVar.getInstances()) {
            if (startVN != varnode) {
                // Make sure all instances are in the worklist
                ptrRef = new PointerRef(startVN, varnode, 0);
                workList.add(ptrRef);
                collectedPtrRef.add(getPointerRefSig(ptrRef.base, ptrRef.current, ptrRef.offset));
                Logging.debug("[WorkList] Adding " + ptrRef);
            }
        }
    }


    /**
     * Update worklist.
     * Be careful, some varnode looks identical, but actually they have different uniqueId.
     * So they are different varnodes.
     * @param newRef the new reference varnode in the PointerRef
     * @param base the base varnode in the PointerRef
     * @param offset the offset between newRef and base
     */
    private void updateWorkList(Varnode newRef, Varnode base, long offset) {
        if (!(newRef instanceof VarnodeAST ast)) {
            Logging.warn("Varnode is not VarnodeAST: " + newRef.toString());
            return;
        }

        if (collectedPtrRef.contains(getPointerRefSig(base, newRef, offset))) {
            return;
        }

//        if (output.getHigh().getSymbol() == null) {
//            workList.add(new PointerRef(output, offset));
//            Logging.debug(String.format(
//                    "[WorkList] Adding varnodeAST-%d %s with offset 0x%x",
//                    ast.getUniqueId(), ast, offset));
//        } else {
//            addRootToWorkList(output.getHigh());
//            Logging.debug(String.format(
//                    "[WorkList] Adding HighVariable %s -> varnodeAST-%d %s with offset 0x%x",
//                    output.getHigh().getName(), ast.getUniqueId(), ast, offset));
//        }
        var ptrRef = new PointerRef(base, newRef, offset);
        workList.add(ptrRef);
        collectedPtrRef.add(getPointerRefSig(ptrRef.base, ptrRef.current, ptrRef.offset));
        Logging.debug("[WorkList] Adding " + ptrRef);
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

    public String getPointerRefSig(Varnode base, Varnode ref, long off) {
        return ((VarnodeAST)base).getUniqueId() + "-" + ((VarnodeAST)ref).getUniqueId() + "-" + off;
    }
}
