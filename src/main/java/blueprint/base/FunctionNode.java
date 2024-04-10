package blueprint.base;

import blueprint.utils.Logging;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class FunctionNode extends NodeBase<Function> {
    public List<HighSymbol> parameters = new LinkedList<>();
    public VariableStorage returnStorage = null;
    public Set<HighSymbol> localVariables = new HashSet<>();

    HighFunction hFunc = null;

    public FunctionNode(Function value, int id) {
        super(value, id);
    }


    public void setHighFunction(HighFunction hFunc) {
        if (this.hFunc == null) {
            this.hFunc = hFunc;
            parsePrototype();
        }
    }

    public HighFunction getHighFunction() {
        return this.hFunc;
    }


    /**
     * Parse function's prototype based on HighFunction.
     * in Ghidra, function's param and return information will not be stored in `Function` in ghidra listing model.
     * This information can be found in `HighFunction` and we can utilize `HighFunctionDBUtil.commitParamsToDatabase`
     * to sync this information to database.
     */
    private void parsePrototype() {
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

        var localSymMap = hFunc.getLocalSymbolMap();
        for (Iterator<HighSymbol> it = localSymMap.getSymbols(); it.hasNext(); ) {
            var sym = it.next();
            if (parameters.contains(sym)) {
                continue;
            }
            localVariables.add(sym);
        }

        // Commit to database, then types and return can be found in Listing model
        // And Information can be accessed by Function.getParameters()
        try {
            HighFunctionDBUtil.commitParamsToDatabase(hFunc, true, SourceType.DEFAULT);
            HighFunctionDBUtil.commitReturnToDatabase(hFunc, SourceType.DEFAULT);
        } catch (Exception e) {
            Logging.error("Failed to commit parameters and return to database");
        }

        assert value.getParameters().length == parameters.size();
    }
}
