import ghidra.app.script.GhidraScript;

public class statistics extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Statistics for " + currentProgram.getName());
        println("Number of functions: " + currentProgram.getFunctionManager().getFunctionCount());
        println("Number of instructions: " + currentProgram.getListing().getNumInstructions());
        println("Number of bytes: " + currentProgram.getMemory().getSize());
    }
}