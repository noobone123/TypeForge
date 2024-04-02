package blueprint.base;

import ghidra.program.model.listing.Function;

public class FunctionNode extends NodeBase<Function> {
    public FunctionNode(Function value, int id) {
        super(value, id);
    }
}
