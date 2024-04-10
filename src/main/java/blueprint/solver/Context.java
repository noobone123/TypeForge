package blueprint.solver;

import ghidra.program.model.pcode.Varnode;
import org.python.modules._hashlib;

import java.util.HashSet;
import java.util.LinkedList;

public class Context {

    public static class PointerRef {
        Varnode varnode;		// The traced Varnode
        long offset;			// Offset relative to original pointer

        public PointerRef(Varnode ref, long off) {
            varnode = ref;
            offset = off;
        }
    }

    public LinkedList<PointerRef> todoList;
    public HashSet<PointerRef> doneSet;

    public Context() {
        todoList = new LinkedList<>();
        doneSet = new HashSet<>();
    }

    public void addPointerRef(Varnode ref, long off) {
        todoList.add(new PointerRef(ref, off));
    }

}
