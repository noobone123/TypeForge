package blueprint.base;

import blueprint.utils.Logging;

import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;

import java.util.List;
import java.util.LinkedList;
import java.util.Set;
import java.util.HashSet;

public class FunctionNode extends NodeBase<Function> {
    public List<HighSymbol> parameters = new LinkedList<>();
    public Set<Object> returnValues = new HashSet<>();
    public Set<Object> localVariables = new HashSet<>();

    HighFunction hFunc = null;

    public FunctionNode(Function value, int id) {
        super(value, id);
    }


    public void setHighFunction(HighFunction hFunc) {
        if (this.hFunc == null) {
            this.hFunc = hFunc;
            parseProtoType();
        }
    }

    public HighFunction getHighFunction() {
        return this.hFunc;
    }


    private void parseProtoType() {
        var funcProto = hFunc.getFunctionPrototype();
        for (int index = 0; index < funcProto.getNumParams(); index++) {
            var param = funcProto.getParam(index);
            parameters.add(param);
        }

        // TODO: parse return values
    }

}
