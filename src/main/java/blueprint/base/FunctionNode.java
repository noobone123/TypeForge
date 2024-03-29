package blueprint.base;

import ghidra.program.model.listing.Function;

public class FunctionNode extends NodeBase<Function> {
    /**
     * Create a function node from the given parameter
     */
    public FunctionNode(Function value, int id) {
        super(value, id);
    }
}
