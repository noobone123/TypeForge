package blueprint.utils;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.flatapi.FlatProgramAPI;
/**
 * The global state of the current analysis.
 */
public class GlobalState {
    public static Program currentProgram;
    public static FlatProgramAPI flatAPI;
    public static GhidraScript ghidraScript;
}
