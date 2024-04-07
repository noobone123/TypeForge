package blueprint.base;

import blueprint.utils.Logging;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

import java.util.List;
import java.util.LinkedList;
import java.util.Set;
import java.util.HashSet;

public class FunctionNode extends NodeBase<Function> {
    List<Object> parameters = new LinkedList<>();
    Set<Object> returnValues = new HashSet<>();
    Set<Object> localVariables = new HashSet<>();

    HighFunction hFunc = null;

    public FunctionNode(Function value, int id) {
        super(value, id);
    }


    public void setHighFunction(HighFunction hFunc) {
        if (this.hFunc == null) {
            this.hFunc = hFunc;
        }
    }

    public HighFunction getHighFunction() {
        return this.hFunc;
    }
}
