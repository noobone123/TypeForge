package blueprint.base.node;

import blueprint.utils.DecompilerHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class FunctionNode extends NodeBase<Function> {
    public List<HighSymbol> parameters = new LinkedList<>();
    public VariableStorage returnStorage = null;
    public Set<HighSymbol> localVariables = new HashSet<>();
    public Set<HighSymbol> globalVariables = new HashSet<>();

    /** Whether the function is a leaf node in the call graph */
    public boolean isLeaf = false;

    public boolean isMeaningful = false;
    public boolean isExternal = false;
    public boolean isNormal = false;

    public HighFunction hFunc = null;
    public ArrayList<ClangLine> lines;
    public ArrayList<ClangToken> tokens = new ArrayList<>();
    DecompileResults decompileResults = null;

    public FunctionNode(Function value, int id) {
        super(value, id);
    }

    public void setDecompileResult (DecompileResults res) {
        this.decompileResults = res;
        this.hFunc = res.getHighFunction();
        if (updatePrototype()) {
            updateLocalVariables();
            updateGlobalVariables();
        } else {
            this.decompile();
        }
    }

    /**
     * Sync high function's prototype to database.
     * in Ghidra, function's param and return information will not be stored in `Function` in ghidra listing model.
     * This information can be found in `HighFunction` and we can utilize `HighFunctionDBUtil.commitParamsToDatabase`
     * to sync this information to database.
     */
    private boolean updatePrototype() {
        if (hFunc == null) {
            Logging.warn("HighFunction is not set");
            return false;
        }

        var funcProto = hFunc.getFunctionPrototype();

        // IMPORTANT: so dirty, avoid ghidra's func prototype parse error due to XMM registers
        if (funcProto.getNumParams() >= 10) {
            fixFuncProto(funcProto);
            return false;
        }
        else {
            for (int i = 0; i < funcProto.getNumParams(); i++) {
                var param = funcProto.getParam(i);
                parameters.add(param);
            }
        }

        returnStorage = funcProto.getReturnStorage();
        return true;

        // Commit to database, then types and return can be found in Listing model
        // And Information can be accessed by Function.getParameters()
        /* WARNING: `commitParamsToDatabase` method may cause some function's wrong prototype be committed to database
                    and wrong prototype will be propagated to other functions. Cause other functions' prototype be wrong.
                    For example: `log_error` is a function that has variable parameters, and using SSE register, it seems
                    that ghidra performs poorly on recognizing its prototype.
        try {
            HighFunctionDBUtil.commitParamsToDatabase(hFunc, true, SourceType.DEFAULT);
            HighFunctionDBUtil.commitReturnToDatabase(hFunc, SourceType.DEFAULT);
        } catch (Exception e) {
            Logging.error("Failed to commit parameters and return to database");
        }

        assert value.getParameters().length == parameters.size(); */
    }

    /**
     * Parse local variables from HighFunction.
     * !IMPORTANT: This method should be called after `parsePrototype` method.
     */
    private void updateLocalVariables() {
        var localSymMap = hFunc.getLocalSymbolMap();
        for (Iterator<HighSymbol> it = localSymMap.getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            if (parameters.contains(sym)) {
                continue;
            }
            localVariables.add(sym);
        }
    }

    private void updateGlobalVariables() {
        var globalSymMap = hFunc.getGlobalSymbolMap();
        for (Iterator<HighSymbol> it = globalSymMap.getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            globalVariables.add(sym);
        }
    }


    private void fixFuncProto(FunctionPrototype proto) {
        var newParams = new ArrayList<HighSymbol>();
        for (var i = 0; i < proto.getNumParams(); i++) {
            var param = proto.getParam(i);
            if (param.getStorage().getRegister().getName().contains("XMM")) {
                Logging.warn("Remove XMM register parameter: " + param.getName());
            } else {
                newParams.add(param);
            }
        }

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
        Logging.info("Fixed function prototype: " + this.value.getName());
    }


    /**
     * Decompile current function
     */
    public void decompile() {
        DecompInterface ifc = DecompilerHelper.setUpDecompiler(null);
        try {
            if (!ifc.openProgram(Global.currentProgram)) {
                Logging.error("Failed to use the decompiler");
                return;
            }

            DecompileResults decompileRes = ifc.decompileFunction(value, 30, TaskMonitor.DUMMY);
            if (!decompileRes.decompileCompleted()) {
                Logging.error("Function decompile failed" + value.getName());
            } else {
                Logging.info("Decompiled function " + value.getName());
                setDecompileResult(decompileRes);
            }

        } finally {
            ifc.dispose();
        }
    }

    public String getC() {
        return decompileResults.getDecompiledFunction().getC();
    }
}
