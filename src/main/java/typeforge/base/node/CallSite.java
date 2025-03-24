package typeforge.base.node;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.List;

public class CallSite {
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

    @Override
    public int hashCode() {
        return callOp.hashCode() * 31 + calleeAddr.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof CallSite other)) {
            return false;
        }
        return this.callOp.equals(other.callOp) && this.calleeAddr.equals(other.calleeAddr);
    }
}