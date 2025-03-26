package typeforge.base.node;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import jnr.ffi.Struct;

import java.util.ArrayList;
import java.util.List;

public class CallSite {
    public Function caller;
    public Address calleeAddr;
    public PcodeOp callOp;
    public List<Varnode> arguments;
    public Varnode receiver;
    private boolean hasReceiver = false;

    public CallSite(Function caller, Address CalleeAddr, PcodeOp callOp) {
        this.caller = caller;
        this.calleeAddr = CalleeAddr;
        this.callOp = callOp;
        this.arguments = new ArrayList<>();
        for (int i = 1; i < callOp.getNumInputs(); i++) {
            arguments.add(callOp.getInput(i));
        }

        receiver = callOp.getOutput();
        if (receiver != null) {
            hasReceiver = true;
        }
    }

    public boolean hasReceiver() {
        return hasReceiver;
    }

    @Override
    public String toString() {
        // It's really hard for ghidra to get the asm addr from pcode, so we use the BasicBlock addr instead.
        return String.format(
                "CallSite{BBAddr=%s}",
                callOp.getParent().getStart().toString()
        );
    }

    @Override
    public int hashCode() {
        return caller.hashCode() * 31 + calleeAddr.hashCode() * 17 + callOp.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof CallSite other)) {
            return false;
        }
        return this.caller.equals(other.caller) &&
                this.calleeAddr.equals(other.calleeAddr) &&
                this.callOp.equals(other.callOp);
    }
}