package blueprint.base.passes;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SlidingWindow {
    public final Skeleton curSkt;
    public final List<Long> offsetList;

    private int currentWindowSize;
    private List<Object> windowElements;
    private List<Long> windowElementsOffsets;
    private int flattenCnt;
    private long flattenStartOffset;
    private long flattenEndOffset;

    public SlidingWindow(Skeleton curSkt, List<Long> offsetList, int initialWindowSize) {
        this.curSkt = curSkt;
        this.offsetList = offsetList;
        this.currentWindowSize = initialWindowSize;
    }

    public boolean tryMatchingFromCurrentOffset(int curOffsetIndex) {
        Optional<List<Object>> windowOpt = getWindowAtOffset(curOffsetIndex);
        if (windowOpt.isEmpty()) {
            return false;
        }

        List<Object> window = windowOpt.get();
        final int threshold = 3;
        int matchCount = 0;

        flattenStartOffset = offsetList.get(curOffsetIndex);
        flattenEndOffset = flattenStartOffset;

        for (int i = curOffsetIndex + currentWindowSize; i < offsetList.size(); i += currentWindowSize) {
            Optional<List<Object>> candidateWindowOpt = getWindowAtOffset(i);
            if (candidateWindowOpt.isEmpty()) {
                break;
            }

            List<Object> candidateWindow = candidateWindowOpt.get();
            if (windowsAreEqual(window, candidateWindow)) {
                matchCount++;
                flattenEndOffset = offsetList.get(i + currentWindowSize - 1);
            } else {
                break;
            }
        }

        if (matchCount >= threshold) {
            windowElements = window;
            flattenCnt = matchCount;
            return true;
        } else {
            return false;
        }
    }

    public void updateWindowSize(int newWindowSize) {
        this.currentWindowSize = newWindowSize;
    }

    public int getFlattenCount() {
        return flattenCnt;
    }

    public long getFlattenStartOffset() {
        return flattenStartOffset;
    }

    public long getFlattenEndOffset() {
        return flattenEndOffset;
    }

    public List<DataType> getWindowDataTypes(int offsetIndex) {
        List<DataType> windowDataTypes = new ArrayList<>();
        for (int i = 0; i < windowElements.size(); i++) {
            var offset = offsetList.get(offsetIndex + i);
            var element = windowElements.get(i);
            if (element instanceof Skeleton) {
                var dt = DataTypeHelper.getPointerDT(DataTypeHelper.getDataTypeByName("void"),
                        curSkt.ptrLevel.get(offset));
                windowDataTypes.add(dt);
            } else if (element instanceof AccessPoints.APSet apSet) {
                windowDataTypes.add(apSet.mostAccessedDT);
            } else {
                Logging.error("SlidingWindow", "Unknown element type in window");
                System.exit(1);
            }
        }
        return windowDataTypes;
    }

    private Optional<List<Object>> getWindowAtOffset(int startIndex) {
        if (startIndex + currentWindowSize > offsetList.size()) {
            return Optional.empty();
        }

        List<Object> window = new ArrayList<>();
        Long prevOffset = null;

        for (int i = 0; i < currentWindowSize; i++) {
            var currentOffset = offsetList.get(startIndex + i);
            if (curSkt.isInconsistentOffset(currentOffset)) {
                return Optional.empty();
            }

            Object element = null;
            if (curSkt.finalPtrReference.containsKey(currentOffset)) {
                element = curSkt.finalPtrReference.get(currentOffset);
            } else {
                element = curSkt.finalConstraint.fieldAccess.get(currentOffset);
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
            var e1 = w1.get(i);
            var e2 = w2.get(i);
            if (e1 instanceof Skeleton && e2 instanceof Skeleton) {
                if (!e1.equals(e2)) { return false; }
            } else if (e1 instanceof AccessPoints.APSet s1 && e2 instanceof AccessPoints.APSet s2) {
                if (s1.DTSize != s2.DTSize) { return false; }
            } else {
                return false;
            }
        }
        return true;
    }


    private boolean isContiguous(long prevOffset, long curOffset, Object element) {
        long size;
        if (element instanceof Skeleton) {
            size = Global.currentProgram.getDefaultPointerSize();
        } else if (element instanceof AccessPoints.APSet apset) {
            size = apset.mostAccessedDT.getLength();
        } else {
            return false;
        }

        return prevOffset >= (curOffset - size) && prevOffset < curOffset;
    }
}
