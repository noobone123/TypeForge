package blueprint.base.node;

import blueprint.utils.DecompilerHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class FunctionNode extends NodeBase<Function> {
    public List<HighSymbol> parameters = new LinkedList<>();
    public VariableStorage returnStorage = null;
    public Set<HighSymbol> localVariables = new HashSet<>();

    /** Whether the function is a leaf node in the call graph */
    public boolean isLeaf = false;

    public boolean isMeaningful = false;

    HighFunction hFunc = null;
    DecompileResults decompileResults = null;

    public FunctionNode(Function value, int id) {
        super(value, id);
    }

    public void setDecompileResult (DecompileResults res) {
        this.decompileResults = res;
        this.hFunc = res.getHighFunction();
        syncPrototype();
    }

    public HighFunction getHighFunction() {
        return this.hFunc;
    }


    /**
     * Sync high function's prototype to database.
     * in Ghidra, function's param and return information will not be stored in `Function` in ghidra listing model.
     * This information can be found in `HighFunction` and we can utilize `HighFunctionDBUtil.commitParamsToDatabase`
     * to sync this information to database.
     */
    private void syncPrototype() {
        if (hFunc == null) {
            Logging.warn("HighFunction is not set");
            return;
        }

        var funcProto = hFunc.getFunctionPrototype();
        for (int i = 0; i < funcProto.getNumParams(); i++) {
            var param = funcProto.getParam(i);
            parameters.add(param);
        }
        returnStorage = funcProto.getReturnStorage();

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
    private void parseLocalVariable() {
        var localSymMap = hFunc.getLocalSymbolMap();
        for (Iterator<HighSymbol> it = localSymMap.getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            if (parameters.contains(sym)) {
                continue;
            }
            localVariables.add(sym);
        }
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
