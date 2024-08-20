package blueprint.base.passes;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.utils.Global;
import ghidra.program.model.data.DataType;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

public class SlidingWindow {
    public final Skeleton skt;
    public final List<Long> offsetList;

    private int currentWindowSize;

    public SlidingWindow(Skeleton skt, List<Long> offsetList, int initialWindowSize) {
        this.skt = skt;
        this.offsetList = offsetList;
        this.currentWindowSize = initialWindowSize;
    }

    public boolean tryMatchingFromCurrentOffset(int curOffset) {
        Optional<List<Object>> windowOpt = getWindowAtOffset(curOffset);
        if (windowOpt.isEmpty()) {
            return false;
        }

        List<Object> window = windowOpt.get();
        final int threshold = 3;
        int matchCount = 0;

        for (int i = curOffset + currentWindowSize; i < offsetList.size(); i += currentWindowSize) {
            Optional<List<Object>> candidateWindowOpt = getWindowAtOffset(i);
            if (candidateWindowOpt.isEmpty()) {
                break;
            }

            List<Object> candidateWindow = candidateWindowOpt.get();
            if (windowsAreEqual(window, candidateWindow)) {
                matchCount++;
            } else {
                break;
            }
        }

        if (matchCount >= threshold) {
            // TODO:
            return true;
        } else {
            return false;
        }
    }


    public void updateWindowSize(int newWindowSize) {
        this.currentWindowSize = newWindowSize;
    }


    private Optional<List<Object>> getWindowAtOffset(int startIndex) {
        if (startIndex + currentWindowSize > offsetList.size()) {
            return Optional.empty();
        }

        List<Object> window = new ArrayList<>();
        Long prevOffset = null;

        for (int i = 0; i < currentWindowSize; i++) {
            var currentOffset = offsetList.get(startIndex + i);
            if (skt.isInconsistentOffset(currentOffset)) {
                return Optional.empty();
            }

            Object element = null;
            if (skt.finalPtrReference.containsKey(currentOffset)) {
                element = skt.finalPtrReference.get(currentOffset);
            } else {
                var aps = skt.finalConstraint.fieldAccess.get(currentOffset);
                element = aps.mostAccessedDT;
            }

            if (prevOffset != null && !isContiguous(prevOffset, currentOffset, element)) {
                return Optional.empty();
            }

            window.add(element);
            prevOffset = currentOffset;
        }
        return Optional.of(window);
    }


    private boolean windowsAreEqual(List<Object> w1, List<Object> w2) {
        if (w1.size() != w2.size()) {
            return false;
        }
        for (int i = 0; i < w1.size(); i ++) {
            if (!w1.get(i).equals(w2.get(i))) {
                return false;
            }
        }
        return true;
    }


    private boolean isContiguous(long prevOffset, long curOffset, Object element) {
        long size;
        if (element instanceof Skeleton) {
            size = Global.currentProgram.getDefaultPointerSize();
        } else if (element instanceof DataType) {
            size = ((DataType) element).getLength();
        } else {
            return false;
        }

        return prevOffset >= (curOffset - size) && prevOffset < curOffset;
    }
}
