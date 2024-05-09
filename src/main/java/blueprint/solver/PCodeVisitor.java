package blueprint.solver;

import blueprint.base.dataflow.SymbolExpr;
import blueprint.base.dataflow.type.PrimitiveType;
import blueprint.base.node.FunctionNode;
import blueprint.utils.DecompilerHelper;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;

import java.util.*;

import static blueprint.utils.DecompilerHelper.getSigned;

public class PCodeVisitor {

    public Context ctx;
    public FunctionNode funcNode;

    /** The workList queue of current function */
    public LinkedList<PcodeOpAST> workList = new LinkedList<>();

    public PCodeVisitor(FunctionNode funcNode, Context ctx) {
        this.funcNode = funcNode;
        this.ctx = ctx;
    }

    /**
     * Prepare the PCodeVisitor for running on-demand data-flow analysis.
     * In detail:
     * 1. we need to collect the candidate highSymbol's corresponding varnodes and mark them as interested varnodes.
     * 2. initialize the dataFlowFacts using the interested varnodes
     * 2. initialize the workList
     */
    public void prepare() {
        // initialize the workList
        for (var bb: funcNode.hFunc.getBasicBlocks()) {
            var iter = bb.getIterator();
            while (iter.hasNext()) {
                PcodeOp op = iter.next();
                workList.add((PcodeOpAST) op);
            }
        }
    }

    /**
     * Run the on-demand data-flow analysis.
     */
    public void run() {
        while (!workList.isEmpty()) {
            var pcode = workList.poll();
            var opCode = pcode.getOpcode();

            switch (opCode) {
                case PcodeOp.INT_ADD, PcodeOp.INT_SUB -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleAddOrSub(pcode);
                    }
                }
                case PcodeOp.COPY, PcodeOp.CAST -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleAssign(pcode);
                    }
                }
                case PcodeOp.PTRADD -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handlePtrAdd(pcode);
                    }
                }
                case PcodeOp.PTRSUB -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handlePtrSub(pcode);
                    }
                }
                case PcodeOp.MULTIEQUAL -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleMultiEqual(pcode);
                    }
                }
                case PcodeOp.LOAD -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleLoad(pcode);
                    }
                }
                case PcodeOp.STORE -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleStore(pcode);
                    }
                }
                case PcodeOp.CALL -> {
                    if (ctx.isInterestedPCode(funcNode, pcode)) {
                        Logging.debug("[PCode] " + pcode);
                        handleCall(pcode);
                    }
                }
            }
        }

        ctx.buildComplexType(funcNode);
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

        var inputFact = ctx.getIntraDataFlowFacts(funcNode, inputs[0]);
        assert inputFact != null;

        ctx.addTracedVarnode(funcNode, output);

        for (var symExpr: inputFact) {
            newOff = symExpr.offset +
                (pcodeOp.getOpcode() == PcodeOp.INT_ADD ? getSigned(inputs[1]) : -getSigned(inputs[1]));

            if (OffsetSanityCheck(newOff)) {
                ctx.addNewSymbolExpr(funcNode, output, symExpr.baseSymbol, newOff);
            }
        }
    }


    private void handleAssign(PcodeOp pcodeOp) {
        var inputVn = pcodeOp.getInput(0);
        var outputVn = pcodeOp.getOutput();

        var inputFact = ctx.getIntraDataFlowFacts(funcNode, inputVn);
        assert inputFact != null;

        ctx.addTracedVarnode(funcNode, outputVn);
        for (var symExpr: inputFact) {
            ctx.addNewSymbolExpr(funcNode, outputVn, symExpr.baseSymbol, symExpr.offset);

            // TODO: is this setSymbolAlias robust enough?
            var inputSymbol = inputVn.getHigh().getSymbol();
            var outputSymbol = outputVn.getHigh().getSymbol();
            if (inputSymbol != null && outputSymbol != null && inputSymbol != outputSymbol) {
                var inputOffset = symExpr.offset;
                var outputOffset = 0;
                ctx.updateSymbolAliasMap(inputSymbol, inputOffset, outputSymbol, outputOffset);
            }
        }
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

        var inputFact = ctx.getIntraDataFlowFacts(funcNode, inputs[0]);
        assert inputFact != null;
        ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());

        for (var symExpr: inputFact) {
            long newOff = symExpr.offset + getSigned(inputs[1]) * getSigned(inputs[2]);
            if (OffsetSanityCheck(newOff)) {
                ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), symExpr.baseSymbol, newOff);
            }
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
        var inputFact = ctx.getIntraDataFlowFacts(funcNode, inputs[0]);
        assert inputFact != null;

        ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());

        for (var symExpr: inputFact) {
            long newOff = symExpr.offset + getSigned(inputs[1]);
            if (OffsetSanityCheck(newOff)) {
                ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), symExpr.baseSymbol, newOff);
            }
        }
    }


    private void handleMultiEqual(PcodeOp pcodeOp) {
        var output = pcodeOp.getOutput();
        var inputs = pcodeOp.getInputs();
        for (var input : inputs) {
            ctx.mergeSymbolExpr(funcNode, input, output, false);
        }
    }


    private void handleCall(PcodeOp pcodeOp) {
        var calleeAddr = pcodeOp.getInput(0).getAddress();
        var calleeNode = ctx.callGraph.getNodebyAddr(calleeAddr);
        if (!ctx.isFunctionSolved(calleeNode)) {
            Logging.warn("Callee function is not solved yet: " + calleeNode.value.getName());
            return;
        }

        // TODO: how to handle cases when arguments and parameters are inconsistency?
        for (int inputIdx = 1; inputIdx < pcodeOp.getNumInputs(); inputIdx++) {
            var argVn = pcodeOp.getInput(inputIdx);
            var argFacts = ctx.getIntraDataFlowFacts(funcNode, argVn);
            for (var symExpr : argFacts) {
                var param = calleeNode.parameters.get(inputIdx - 1);
                ctx.updateSymbolAliasMap(symExpr, new SymbolExpr(param, 0));
            }
        }
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

        // TODO: handle the ComplexType
        // The amount of data loaded by this instruction is determined by the size of the output variable
        DataType outDT = DecompilerHelper.getDataTypeTraceForward(output);

        for (var symExpr : ctx.getIntraDataFlowFacts(funcNode, input)) {
            var type = new PrimitiveType(outDT);
            ctx.updateLoadStoreMap(funcNode, pcodeOp, symExpr, type, true);
        }

        // TODO: tracing the dataflow of load op's output varnode?
    }

    /**
     * Same as handleLoad, but for STORE operation
     */
    private void handleStore(PcodeOp pcodeOp) {
        // the slot index of cur.varnode is 1, which means this varnode
        // represent the memory location to be stored
        var storedAddrVn = pcodeOp.getInput(1);
        var storedValueDT = DecompilerHelper.getDataTypeTraceBackward(pcodeOp.getInput(2));

        for (var symExpr : ctx.getIntraDataFlowFacts(funcNode, storedAddrVn)) {
            var type = new PrimitiveType(storedValueDT);
            ctx.updateLoadStoreMap(funcNode, pcodeOp, symExpr, type, false);
        }
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
