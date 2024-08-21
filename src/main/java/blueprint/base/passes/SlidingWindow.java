package blueprint.base.passes;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;

import java.util.*;

public class SlidingWindow {
    public final Skeleton curSkt;
    public final List<Long> offsetList;

    private int windowCapacity;
    private Map<Long, Object> windowElements;
    private long alignedWindowSize;
    private int flattenCnt;

    public SlidingWindow(Skeleton curSkt, List<Long> offsetList, int initialWindowCapacity) {
        this.curSkt = curSkt;
        this.offsetList = offsetList;
        this.windowCapacity = initialWindowCapacity;
    }

    public boolean tryMatchingFromCurrentOffset(int curOffsetIndex) {
        Optional<Map<Long, Object>> windowOpt = getWindowAtOffset(curOffsetIndex);
        if (windowOpt.isEmpty()) {
            return false;
        }

        Map<Long, Object> window = windowOpt.get();
        final int threshold = 4;
        int matchCount = 0;
        alignedWindowSize = getAlignedWindowSize(window);
        long prevWindowStartOffset = offsetList.get(curOffsetIndex);

        for (int i = curOffsetIndex + windowCapacity; i < offsetList.size(); i += windowCapacity) {
            Optional<Map<Long, Object>> candidateWindowOpt = getWindowAtOffset(i);
            if (candidateWindowOpt.isEmpty()) {
                break;
            }

            Map<Long, Object> candidateWindow = candidateWindowOpt.get();
            if (windowsAreEqual(window, candidateWindow)) {
                if ((offsetList.get(i) - prevWindowStartOffset) == alignedWindowSize) {
                    matchCount++;
                    prevWindowStartOffset = offsetList.get(i);
                } else {
                    Logging.info("SlidingWindow",
                            String.format("Window equal but not contiguous: \n Window: %s\n Aligned Size: %d\n PrevWindowStart: %s, CurrentWindowStart: %s",
                                    window, alignedWindowSize, prevWindowStartOffset, offsetList.get(i)));
                    break;
                }
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
        this.windowCapacity = newWindowSize;
    }

    public int getFlattenCount() {
        return flattenCnt;
    }

    public long getAlignedWindowSize() {
        return alignedWindowSize;
    }

    public DataType getWindowDataTypes() {
        // TODO: create data type from `windowElements`
        return null;
    }

    private Optional<Map<Long, Object>> getWindowAtOffset(int startIndex) {
        if (startIndex + windowCapacity > offsetList.size()) {
            return Optional.empty();
        }

        Map<Long, Object> window = new TreeMap<>();
        long prevOffset = -1;
        long startOffset = offsetList.get(startIndex);

        for (int i = 0; i < windowCapacity; i++) {
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

            if (prevOffset != -1 && !isContiguous(prevOffset, currentOffset, element)) {
                return Optional.empty();
            }

            window.put(currentOffset - startOffset, element);
            prevOffset = currentOffset;
        }
        return Optional.of(window);
    }


    private boolean windowsAreEqual(Map<Long, Object> w1, Map<Long, Object> w2) {
        if (w1.size() != w2.size()) {
            return false;
        }

        if (!w1.keySet().equals(w2.keySet())) {
            return false;
        }

        for (var entry1: w1.entrySet()) {
            var offset = entry1.getKey();
            Object e1 = entry1.getValue();
            Object e2 = w2.get(offset);

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

    /**
     * Get the Aligned Window's Size
     * @return aligned window's size
     */
    private long getAlignedWindowSize(Map<Long, Object> window) {
        long totalSize = 0;
        long maxAlignSize = 1;
        for (var element: window.values()) {
            long fieldSize;
            long fieldAlignSize = 1;
            if (element instanceof Skeleton) {
                fieldSize = Global.currentProgram.getDefaultPointerSize();
                fieldAlignSize = fieldSize;
            }
            else {
                fieldSize = ((AccessPoints.APSet) element).mostAccessedDT.getLength();
                fieldAlignSize = ((AccessPoints.APSet) element).mostAccessedDT.getAlignment();
            }

            if (totalSize % fieldAlignSize != 0) {
                totalSize += fieldAlignSize - (totalSize % fieldAlignSize);
            }

            totalSize += fieldSize;
            if (fieldAlignSize > maxAlignSize) {
                maxAlignSize = fieldAlignSize;
            }
        }

        if (totalSize % maxAlignSize != 0) {
            totalSize += maxAlignSize - (totalSize % maxAlignSize);
        }

        return totalSize;
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
