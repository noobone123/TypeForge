package blueprint.solver;

import blueprint.base.node.FunctionNode;
import blueprint.utils.DecompilerHelper;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;

import java.util.*;

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

        public PointerRef(Varnode ref, Varnode base, long off) {
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
    public FunctionNode funcNode;

    /** We only collect data-flow related to interested varnodes */
    public Set<Varnode> interestedVn = new HashSet<>();

    /** The workList queue of current function */
    public LinkedList<PcodeOpAST> workList = new LinkedList<>();

    /** Dataflow facts collected from the current function */
    public HashMap<Varnode, PointerRef> dataFlowFacts = new HashMap<>();

    /** This aliasMap should be traced recursively manually, for example: a->b, b->c, but a->c will not be recorded */
    public HashMap<Varnode, HashSet<Varnode>> aliasMap = new HashMap<>();

    /** These 2 maps are used to record the DataType's load/store operation on insteseted varnodes */
    public HashMap<PointerRef, DataType> loadMap = new HashMap<>();
    public HashMap<PointerRef, DataType> storeMap = new HashMap<>();

    public PCodeVisitor(FunctionNode funcNode, Context ctx) {
        this.funcNode = funcNode;
        this.ctx = ctx;
    }

    /**
     * Prepare the PCodeVisitor for running flow-sensitive, on-demand data-flow analysis.
     * In detail:
     * 1. we need to collect the candidate highSymbol's corresponding varnodes and mark them as interested varnodes.
     * 2. initialize the dataFlowFacts using the interested varnodes
     * 2. initialize the workList
     * @param candidates the list of HighSymbols that need to collect data-flow facts
     */
    public void prepare(List<HighSymbol> candidates) {
        initDataFlowFacts(candidates);

        // update the workList
        for (var bb: funcNode.hFunc.getBasicBlocks()) {
            var iter = bb.getIterator();
            while (iter.hasNext()) {
                PcodeOp op = iter.next();
                workList.add((PcodeOpAST) op);
            }
        }
    }


    private void initDataFlowFacts(List<HighSymbol> candidates) {
        // Update the interestedVn
        for (var candidate: candidates) {
            var highVar = candidate.getHighVariable();
            Logging.info("HighSymbol: " + candidate.getName());

            // If a HighSymbol (like a parameter) is not be used in the function, it can not hold a HighVariable
            if (highVar == null) {
                Logging.warn(funcNode.value.getName() + " -> HighSymbol: " + candidate.getName() + " has no HighVariable");
                continue;
            }

            // Add all varnode instances of the HighVariable to the interestedVn
            interestedVn.addAll(Arrays.asList(highVar.getInstances()));

            // Initialize the dataFlowFacts using the interested varnodes
            for (var vn: highVar.getInstances()) {
                var startVn = highVar.getRepresentative();
                dataFlowFacts.put(vn, new PointerRef(vn, startVn, 0));
            }
        }
    }


    /**
     * If the PCodeOp's input varnodes is related to the interested varnode, then we should handle it.
     * @param pcode the PCodeOp
     * @return true if the PCodeOp is related to the interested varnode
     */
    private boolean isInterestedPCode(PcodeOpAST pcode) {
        for (var vn: pcode.getInputs()) {
            if (interestedVn.contains(vn)) {
                return true;
            }
        }
        return false;
    }


    private PointerRef getDataFlowFact(Varnode vn) {
        var res = dataFlowFacts.get(vn);
        if (res == null) {
            Logging.warn("Failed to get dataflow fact for " + vn);
            return null;
        }
        return res;
    }

    /**
     * Run the flow-sensitive, on-demand data-flow analysis.
     */
    public void run() {
        while (!workList.isEmpty()) {
            var pcode = workList.poll();
            var opCode = pcode.getOpcode();

            switch (opCode) {
                case PcodeOp.INT_ADD, PcodeOp.INT_SUB -> {
                    if (isInterestedPCode(pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleAddOrSub(pcode);
                    }
                }
                case PcodeOp.COPY, PcodeOp.CAST -> {
                    if (isInterestedPCode(pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleAssign(pcode);
                    }
                }
                case PcodeOp.PTRADD -> {
                    if (isInterestedPCode(pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handlePtrAdd(pcode);
                    }
                }
                case PcodeOp.PTRSUB -> {
                    if (isInterestedPCode(pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handlePtrSub(pcode);
                    }
                }
                case PcodeOp.MULTIEQUAL -> {
                    if (isInterestedPCode(pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleMultiEqual(pcode);
                    }
                }
                case PcodeOp.LOAD -> {
                    if (isInterestedPCode(pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleLoad(pcode);
                    }
                }
                case PcodeOp.STORE -> {
                    if (isInterestedPCode(pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleStore(pcode);
                    }
                }
            }
        }
    }


    /**
     * update IntraSolver's context with the collected data-flow facts.
     */
    public void updateContext() {
        // TODO: handle alias and TypeBuilder ...
        loadMap.forEach((ptrRef, dt) -> {
            var base = ptrRef.base;
            var offset = ptrRef.offset;
            var highSymbol = base.getHigh().getSymbol();
            ctx.addField(highSymbol, offset, dt);
        });

        storeMap.forEach((ptrRef, dt) -> {
            var base = ptrRef.base;
            var offset = ptrRef.offset;
            var highSymbol = base.getHigh().getSymbol();
            ctx.addField(highSymbol, offset, dt);
        });
    }


    /**
     * If parameter is an ADD or SUB operation, we can calculate the new offset
     * But remember, only varnode_1 = varnode_0 + const is not enough to prove that
     * varnode_0 is a base address of structure.
     * For example:
     * b = a + 4 is just a simple arithmetic operation, it does not mean that `a` is a base address of a structure.
     * But if there is a load/store operation like:
     * c = *(a + 4) or *(a + 4) = c, then we can say that `a` is a base address of a structure.
     * @param pcodeOp the PCodeOpAST
     */
    private void handleAddOrSub(PcodeOpAST pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        Varnode output = pcodeOp.getOutput();
        long newOff;

        if (!inputs[1].isConstant()) {
            return;
        }

        var inputFact = getDataFlowFact(inputs[0]);
        assert inputFact != null;

        newOff = inputFact.offset +
            (pcodeOp.getOpcode() == PcodeOp.INT_ADD ? getSigned(inputs[1]) : -getSigned(inputs[1]));

        if (!OffsetSanityCheck(newOff)) {
            return;
        }

        updateDataFlowFacts(output, inputFact.base, newOff);
        addInterestedVn(output);
    }


    private void handleAssign(PcodeOp pcodeOp) {
        var inputVn = pcodeOp.getInput(0);
        var outputVn = pcodeOp.getOutput();

        var inputFact = getDataFlowFact(inputVn);
        assert inputFact != null;

        updateDataFlowFacts(outputVn, inputFact.base, inputFact.offset);
        updateAliasMap(inputVn, outputVn);
        addInterestedVn(outputVn);

        // TODO: restrict the aliasing to only pointer Type?
//        if (ctx.setAliasIntra(inputSymbol, outputSymbol)) {
//            Logging.debug(
//                    String.format("[Align] Aligning dataflow facts from %s to %s",
//                            inputSymbol.getName(), outputSymbol.getName())
//                );
//        }
    }


    /**
     * Handle PTRADD operation. In PTRADD operation,
     * output = input0 + input1 * input2, where input0 is array's base address, input1 is index
     * and input2 is element size.
     * @param pcodeOp The PCodeOp
     */
    private void handlePtrAdd(PcodeOp pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        // TODO: handle the case where input1 or input2 is not constant
        if (!inputs[1].isConstant() || !inputs[2].isConstant()) {
            return;
        }

        var inputFact = getDataFlowFact(inputs[0]);
        assert inputFact != null;
        var newOff = inputFact.offset + getSigned(inputs[1]) * getSigned(inputs[2]);
        if (OffsetSanityCheck(newOff)) {
            updateDataFlowFacts(pcodeOp.getOutput(), inputFact.base, newOff);
            addInterestedVn(pcodeOp.getOutput());
        }
    }

    /**
     * A PTRSUB performs the simple pointer calculation, input0 + input1
     * Input0 is a pointer to the beginning of the structure, and input1 is a byte offset to the subcomponent.
     * As an operation, PTRSUB produces a pointer to the subcomponent and stores it in output.
     * @param pcodeOp The PCodeOp
     */
    private void handlePtrSub(PcodeOp pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        if (!inputs[1].isConstant()) {
            return;
        }
        var inputFact = getDataFlowFact(inputs[0]);
        assert inputFact != null;
        var newOff = inputFact.offset + getSigned(inputs[1]);
        if (OffsetSanityCheck(newOff)) {
            updateDataFlowFacts(pcodeOp.getOutput(), inputFact.base, newOff);
            addInterestedVn(pcodeOp.getOutput());
        }
    }


    private void handleMultiEqual(PcodeOp pcodeOp) {
        // TODO: Merging multiple dataflow facts from multiple varnodes?
        var output = pcodeOp.getOutput();
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
     * @param pcodeOp The PCodeOp
     */
    private void handleLoad(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(1);
        var output = pcodeOp.getOutput();

        // The amount of data loaded by this instruction is determined by the size of the output variable
        DataType outDT = DecompilerHelper.getDataTypeTraceForward(output);
        loadMap.put(getDataFlowFact(input), outDT);
        Logging.debug("[Load] " + input + " -> " + outDT);

        // also trace the varnode loaded from addr
        updateDataFlowFacts(output, output, 0);
        addInterestedVn(output);
    }

    /**
     * Same as handleLoad, but for STORE operation
     */
    private void handleStore(PcodeOp pcodeOp) {
        // the slot index of cur.varnode is 1, which means this varnode
        // represent the memory location to be stored
        var storedAddrVn = pcodeOp.getInput(1);
        var storedValueDT = DecompilerHelper.getDataTypeTraceBackward(pcodeOp.getInput(2));

        storeMap.put(getDataFlowFact(storedAddrVn), storedValueDT);
        Logging.debug("[Store] " + storedAddrVn + " -> " + storedValueDT);
        addInterestedVn(storedAddrVn);
    }


    /**
     * Update the dataflow facts with the new reference varnode.
     * Be careful, some varnode looks identical, but actually they have different uniqueId.
     * So they are different varnodes.
     * @param cur the current varnode which indicates the reference
     * @param base the base varnode in the PointerRef
     * @param offset the offset between newRef and base
     */
    private void updateDataFlowFacts(Varnode cur, Varnode base, long offset) {
        if (!(cur instanceof VarnodeAST ast)) {
            Logging.warn("Varnode is not VarnodeAST: " + cur.toString());
            return;
        }

        var newPtrRef = new PointerRef(cur, base, offset);
        dataFlowFacts.put(cur, newPtrRef);
        Logging.debug("[DataFlow] Update dataflow facts: " + newPtrRef);
    }

    private void addInterestedVn(Varnode vn) {
        if (interestedVn.add(vn)) {
            Logging.debug("[Interested] Add interested varnode: " + vn);
        }
    }

    /**
     * Update the alias map to record the aliasing relationship between two varnodes.
     */
    private void updateAliasMap(Varnode a, Varnode b) {
        aliasMap.computeIfAbsent(a, k -> new HashSet<>()).add(b);
        aliasMap.computeIfAbsent(b, k -> new HashSet<>()).add(a);
        Logging.debug("[Alias] Update alias map: " + a + " -> " + b);
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
