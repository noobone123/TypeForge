package blueprint.utils;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.framework.Architecture;
import ghidra.program.model.listing.Program;
import ghidra.program.flatapi.FlatProgramAPI;
/**
 * The global state of the current analysis.
 */
public class Global {
    public static Program currentProgram;
    public static FlatProgramAPI flatAPI;
    public static GhidraScript ghidraScript;
    public static String outputDirectory;
    public static long startAddress;
}
