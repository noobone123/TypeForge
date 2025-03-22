package typeforge.base.node;

import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.program.model.listing.Program;
import typeforge.utils.DataTypeHelper;
import typeforge.utils.DecompilerHelper;
import typeforge.utils.Global;
import typeforge.utils.Logging;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class FunctionNode extends NodeBase<Function> {

    public static class CallSite {
        public Address calleeAddr;
        public PcodeOp callOp;
        public List<Varnode> arguments;

        public CallSite(Address CalleeAddr, PcodeOp callOp) {
            this.calleeAddr = CalleeAddr;
            this.callOp = callOp;
            this.arguments = new ArrayList<>();
            for (int i = 1; i < callOp.getNumInputs(); i++) {
                arguments.add(callOp.getInput(i));
            }
        }
    }


    /** Whether the function is a leaf node in the call graph */
    public boolean isLeaf = false;
    public boolean isMeaningful = false;
    public boolean isExternal = false;
    public boolean isTypeAgnostic = false;
    public boolean isNormal = false;
    public boolean needFixPrototype = false;

    public boolean isVarArg = false;
    public int fixedParamNum = 0;

    public List<HighSymbol> newParams = new ArrayList<>();
    public Map<PcodeOp, CallSite> callSites = new HashMap<>();

    /** Following information should be updated after each decompile */
    public HighFunction hFunc = null;
    public List<PcodeOp> pCodes = new LinkedList<>();
    public PcodeOp returnOp = null;
    DecompileResults decompileResults = null;
    Map<String, HighSymbol> nameToSymbolMap = null;

    public List<HighSymbol> parameters = new LinkedList<>();
    public List<HighSymbol> localVariables = new LinkedList<>();
    public List<HighSymbol> globalVariables = new LinkedList<>();
    public Map<VariableStorage, DataType> decompilerInferredDT = new HashMap<>();

    /** If a local variable is merged, these variables should not appear in TypeAliasGraph
     merged variable's dataType should not be inferred, because there may hold different types */
    public HashSet<HighSymbol> mergedVariables = new HashSet<>();

    public FunctionNode(Function value, int id) {
        super(value, id);
    }

    public void setTypeAgnostic() {
        isTypeAgnostic = true;
    }

    private Optional<List<HighSymbol>> checkPrototype() {
        var funcProto = hFunc.getFunctionPrototype();
        var newParams = new ArrayList<HighSymbol>();
        for (var i = 0; i < funcProto.getNumParams(); i++) {
            var param = funcProto.getParam(i);
            if (param.getStorage().getRegister() != null) {
                if (param.getStorage().getRegister().getName().contains("XMM")) {
                    Logging.warn("FunctionNode", "Remove XMM register parameter: " + param.getName());
                } else {
                    newParams.add(param);
                }
            } else {
                newParams.add(param);
            }
        }

        if (newParams.size() != funcProto.getNumParams()) {
            Logging.info("FunctionNode", String.format("Found %d XMM register parameters in %s", funcProto.getNumParams() - newParams.size(), this.value.getName()));
            return Optional.of(newParams);
        } else {
            return Optional.empty();
        }
    }

    private void fixFuncProto(List<HighSymbol> newParams) {
        // init newParamsDef with newParams
        var newParamsDef = new ParameterDefinition[newParams.size()];
        for (var i = 0; i < newParams.size(); i++) {
            var param = newParams.get(i);
            newParamsDef[i] = new ParameterDefinitionImpl("param_" + (i+1), param.getDataType(), "updated");
        }

        var funcDef = new FunctionDefinitionDataType(this.value, true);
        funcDef.setArguments(newParamsDef);

        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(this.value.getEntryPoint(), funcDef, SourceType.USER_DEFINED);
        Global.ghidraScript.runCommand(cmd);
        Logging.info("FunctionNode", "Fixed function prototype: " + this.value.getName());
    }

    /**
     * We can not fully trust decompiler inferred composite datatype, so we need to record them and fix them into primitive.
     */
    private Optional<Set<HighSymbol>> checkLocalVariables() {
        Set<HighSymbol> reTypeCandidate = new HashSet<>();
        var localSymMap = hFunc.getLocalSymbolMap();
        for (Iterator<HighSymbol> it = localSymMap.getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            var dt = sym.getDataType();
            decompilerInferredDT.put(sym.getStorage(), dt);
            if (DataTypeHelper.isPointerToCompositeDataType(dt)) {
                reTypeCandidate.add(sym);
                Logging.info("FunctionNode", String.format("Found local variable pointed to composite datatype: %s -> %s", sym.getName(), dt.getName()));
            }
        }

        return reTypeCandidate.isEmpty() ? Optional.empty() : Optional.of(reTypeCandidate);
    }


    private void fixLocalVariableDataType(Set<HighSymbol> candidates) {
        for (var sym : candidates) {
            var newDT = DataTypeHelper.getDataTypeByName("void");
            if (newDT == null) {
                Logging.warn("FunctionNode", "Failed to find datatype");
                continue;
            }
            DecompilerHelper.setLocalVariableDataType(sym, newDT, 1);
        }
    }


    private void setParameters() {
        parameters.clear();
        var funcProto = hFunc.getFunctionPrototype();
        var totalParamsNum = isVarArg ? fixedParamNum : funcProto.getNumParams();
        if (totalParamsNum > funcProto.getNumParams()) {
            totalParamsNum = funcProto.getNumParams();
        }
        for (int i = 0; i < totalParamsNum; i++) {
            var param = funcProto.getParam(i);
            parameters.add(param);
        }
    }

    /**
     * Parse local variables from HighFunction.
     * !IMPORTANT: This method should be called after `setParameters` method.
     */
    private void setLocalVariables() {
        localVariables.clear();
        var localSymMap = hFunc.getLocalSymbolMap();
        for (Iterator<HighSymbol> it = localSymMap.getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            if (parameters.contains(sym)) {
                continue;
            }

            var mergedGroups = getMergedGroup(sym);
            if (mergedGroups.size() > 1) {
                Logging.info("FunctionNode", String.format("Found merged local variable: %s: %s", hFunc.getFunction().getName(), sym.getName()));
                mergedVariables.add(sym);
            }
            else {
                localVariables.add(sym);
            }
        }
    }

    private void setGlobalVariables() {
        globalVariables.clear();
        var globalSymMap = hFunc.getGlobalSymbolMap();
        for (Iterator<HighSymbol> it = globalSymMap.getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            globalVariables.add(sym);
        }
    }

    public HighSymbol getHighSymbolbyName(String varName) {
        return nameToSymbolMap.get(varName);
    }

    /**
     * Dump HighVariable's HighPcode
     */
    public void dumpHighPcode() {
        for (var pcode : pCodes) {
            StringBuilder highPCodeInst = new StringBuilder();

            //Output Pcode op's output Varnode
            Varnode outVn = pcode.getOutput();
            if (outVn != null) {
                highPCodeInst.append(DecompilerHelper.getVarnodeString((VarnodeAST) outVn));
            } else {
                highPCodeInst.append("---"); //op with no output
            }

            //Output opcode itself
            highPCodeInst.append("," + " ").append(pcode.getMnemonic());

            //Output Pcode op's input Varnodes
            for (int i = 0; i < pcode.getNumInputs(); ++i) {
                highPCodeInst.append("," + " ").append(DecompilerHelper.getVarnodeString((VarnodeAST) pcode.getInput(i)));
            }

            Logging.info("FunctionNode", highPCodeInst.toString());
        }
    }


    /**
     * Decompile current function
     */
    public boolean decompile() {
        DecompInterface ifc = DecompilerHelper.setUpDecompiler(null);
        try {
            if (!ifc.openProgram(Global.currentProgram)) {
                Logging.error("FunctionNode", "Failed to use the decompiler");
                return false;
            }

            DecompileResults decompileRes = ifc.decompileFunction(value, 30, TaskMonitor.DUMMY);
            if (!decompileRes.decompileCompleted()) {
                Logging.error("FunctionNode", "Function decompile failed" + value.getName());
                return false;
            } else {
                Logging.info("FunctionNode", "Decompiled function " + value.getName());
                updateDecompileResult(decompileRes);
                return true;
            }
        } finally {
            ifc.dispose();
        }
    }

    public void updateDecompileResult(DecompileResults res) {
        this.decompileResults = res;
        this.hFunc = res.getHighFunction();
    }


    public String getC() {
        return decompileResults.getDecompiledFunction().getC();
    }


    public boolean initCheck() {
        // Be careful: fix current function's prototype may influence other function's decompile result
        // So fix function's prototype should be done after all functions are decompiled
        if (needFixPrototype) {
            Logging.info("FunctionNode", "Need to fix function prototype");
            fixFuncProto(this.newParams);
            if (!decompile()) { return false; }
            collectPCodeInfo();
            setParameters();
            setLocalVariables();
            setGlobalVariables();
        }
        return true;
    }


    /**
     * Decompile the function
     */
    public boolean initialize() {
        if (!decompile()) { return false; }
        var newParams = checkPrototype();
        if (newParams.isPresent()) {
            needFixPrototype = true;
            this.newParams = newParams.get();
        }

        var result = checkNeedSplitVariable();
        if (result.isPresent()) {
            var splitCandidates = new HashSet<HighSymbol>(result.get());
            for (var sym : splitCandidates) {
                splitMergedVariables(sym);
            }
            if (!decompile()) {
                return false;
            }
        }

        var fixCandidates = checkLocalVariables();
        if (fixCandidates.isPresent()) {
            Logging.info("FunctionNode", "Found local variables pointed to composite datatype");
            fixLocalVariableDataType(fixCandidates.get());
            if (!decompile()) { return false; }
        }

        collectPCodeInfo();
        setParameters();
        setLocalVariables();
        setGlobalVariables();
        return true;
    }

    public void collectPCodeInfo() {
        returnOp = null;
        callSites.clear();
        for (var block : hFunc.getBasicBlocks()) {
            var iter = block.getIterator();
            while (iter.hasNext()) {
                PcodeOp op = iter.next();
                pCodes.add(op);
                if (op.getOpcode() == PcodeOp.RETURN) {
                    returnOp = op;
                }
                if (op.getOpcode() == PcodeOp.CALL) {
                    var callSite = new CallSite(op.getInput(0).getAddress(), op);
                    callSites.put(op, callSite);
                }
            }
        }
    }

    public Optional<Set<HighSymbol>> checkNeedSplitVariable() {
        Set<HighSymbol> result = new HashSet<>();
        Set<HighSymbol> allHighSymbols = new HashSet<>();
        for (Iterator<HighSymbol> it = hFunc.getLocalSymbolMap().getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            allHighSymbols.add(sym);
        }

        for (var sym: allHighSymbols) {
            var var = sym.getHighVariable();
            if (sym.isIsolated()) {
                continue;
            }
            if (var == null) {
                continue;
            }
            var mergedGroups = getMergedGroup(sym);
            if (mergedGroups.size() > 1) {
                // We only split out parameters high variables
                if (sym.isParameter()) {
                    // If the merged variable is a parameter, we should split it out
                    result.add(sym);
                    Logging.info("FunctionNode", String.format("Found variables need to split: %s", sym.getName()));
                }
            }
        }

        return result.isEmpty() ? Optional.empty() : Optional.of(result);
    }


    private void splitMergedVariables(HighSymbol highSym) {
        var variable = highSym.getHighVariable();
        for (var vn: variable.getInstances()) {
            try {
                HighVariable newVar = hFunc.splitOutMergeGroup(variable, vn);
                HighSymbol newSymbol = newVar.getSymbol();
                Logging.info("FunctionNode", "Split merged variable: " + newSymbol.getName());
            }
            catch (PcodeException e) {
                Logging.warn("FunctionNode", "Failed to split merged variable: " + variable.getName());
                return;
            }

            DataType dt = highSym.getDataType();
            try {
                HighFunctionDBUtil.updateDBVariable(highSym, null, dt, SourceType.USER_DEFINED);
            } catch (Exception e) {
                Logging.warn("FunctionNode", "Failed to update variable: " + variable.getName());
            }
        }
    }

    private Set<Short> getMergedGroup(HighSymbol highSym) {
        Set<Short> mergedGroups = new HashSet<>();
        var variable = highSym.getHighVariable();
        if (variable == null) { return mergedGroups; }
        for (var vn: variable.getInstances()) {
            mergedGroups.add(vn.getMergeGroup());
        }
        return mergedGroups;
    }


    public DataType getDecompilerInferredDT(VariableStorage storage) {
        return decompilerInferredDT.get(storage);
    }
}
