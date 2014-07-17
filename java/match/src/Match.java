import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class Match {
    // 判断文档是否是结构化的
    public static final int TextLengthCutoff = 300;
    // 判断兄弟节点距离的cutoff
    public static final int SiblingDistCutoff = 15;
    // 判断文本距离的cutoff
    public static final int TextDistCutoff = 10;

    private int textLengthCutoff;
    private int siblingDistCutoff;
    private int textDistCutoff;

    public Match(int tlc, int sdc, int tdc) {
        // TODO Auto-generated constructor stub
        textDistCutoff = tlc;
        siblingDistCutoff = sdc;
        textDistCutoff = tdc;
    }

    /**
     * judge whether the document is structurized or not
     * 
     * @param content
     * @return
     */
    public static boolean isStructurized(Elements content) {
        int maxlength = 0;
        for (Element ele : content) {
            int len = ele.parent().ownText().length();
            System.out.println("len:" + len);
            if (maxlength < len)
                maxlength = len;
        }
        if (maxlength > TextLengthCutoff)
            return false;
        else
            return true;
    }

    private boolean _isStructurized(Elements content) {
        int maxlength = 0;
        for (Element ele : content) {
            int len = ele.parent().ownText().length();
            System.out.println("len:" + len);
            if (maxlength < len)
                maxlength = len;
        }
        if (maxlength > this.textLengthCutoff)
            return false;
        else
            return true;
    }

    /**
     * 判断该结构化文档是否是匹配的。
     * 
     * @param content
     * @param query
     * @return
     */
    public static boolean ifMatchInStructure(Elements content,
            HashSet<String> query) {
        if (content.size() > 50)
            return false;
        // 对于每个搜索词q来说，找到与其他搜索词q的最短兄弟距离。若每个最短都小于cutoff，则是真的
        HashMap<String, ArrayList<Element>> queryEleMap = new HashMap<String, ArrayList<Element>>();
        for (Element ele : content) {
            if (!queryEleMap.containsKey(ele.ownText())) {
                queryEleMap.put(ele.ownText(), new ArrayList<Element>());
            } else {
                queryEleMap.get(ele.ownText()).add(ele);
            }
        }

        String[] queries = new String[query.size()];
        queries = query.toArray(queries);

        for (int i = 0; i < queries.length; i++) {
            for (int j = i + 1; j < queries.length; j++) {
                String q = queries[i];
                String o = queries[j];
                ArrayList<Element> qEle = queryEleMap.get(q);
                ArrayList<Element> oEle = queryEleMap.get(o);

                // 初始值很大，即没有逻辑关联
                int siblingDist = 10000;

                for (int m = 0; m < qEle.size(); m++) {
                    for (int n = 0; m < oEle.size(); n++) {
                        // 先从节点距离4进行判断，若不行在对节点距离等于6的判读。
                        Element eleq = qEle.get(m);
                        Element eleo = oEle.get(n);
                        Element qfather = eleq.parent().parent();
                        Element ofather = eleo.parent().parent();
                        if (qfather == ofather) {
                            int indexq = eleq.parent().elementSiblingIndex();
                            int indexo = eleo.parent().elementSiblingIndex();
                            int temp = Math.abs(indexo - indexq);
                            if (temp < siblingDist)
                                siblingDist = temp;
                        } else {
                            // 只是目前这两个element没有共同祖先。兄弟距离视作无穷大。
                            int temp = 100000;
                            if (temp < siblingDist)
                                siblingDist = temp;
                        }
                    }
                    // 判断完q和o的兄弟距离，若其最小兄弟距离<2*cutoff
                    // 为什么是2*cutoff,对于a b c 来说，我们并不知道搜索词中那个是a,哪个是
                    // 所以为了避免这种情况，只好用2*cutoff来当作判断值。
                    if (siblingDist > 2 * SiblingDistCutoff)
                        return false;
                }
            }
        }
        return true;
    }

    private boolean _ifMatchInStructure(Elements content, HashSet<String> query) {
        if (content.size() > 50)
            return false;
        // 对于每个搜索词q来说，找到与其他搜索词q的最短兄弟距离。若每个最短都小于cutoff，则是真的
        HashMap<String, ArrayList<Element>> queryEleMap = new HashMap<String, ArrayList<Element>>();
        for (Element ele : content) {
            if (!queryEleMap.containsKey(ele.ownText())) {
                queryEleMap.put(ele.ownText(), new ArrayList<Element>());
            } else {
                queryEleMap.get(ele.ownText()).add(ele);
            }
        }

        String[] queries = new String[query.size()];
        queries = query.toArray(queries);

        for (int i = 0; i < queries.length; i++) {
            for (int j = i + 1; j < queries.length; j++) {
                String q = queries[i];
                String o = queries[j];
                ArrayList<Element> qEle = queryEleMap.get(q);
                ArrayList<Element> oEle = queryEleMap.get(o);

                // 初始值很大，即没有逻辑关联
                int siblingDist = 10000;

                for (int m = 0; m < qEle.size(); m++) {
                    for (int n = 0; m < oEle.size(); n++) {
                        // 先从节点距离4进行判断，若不行在对节点距离等于6的判读。
                        Element eleq = qEle.get(m);
                        Element eleo = oEle.get(n);
                        Element qfather = eleq.parent().parent();
                        Element ofather = eleo.parent().parent();
                        if (qfather == ofather) {
                            int indexq = eleq.parent().elementSiblingIndex();
                            int indexo = eleo.parent().elementSiblingIndex();
                            int temp = Math.abs(indexo - indexq);
                            if (temp < siblingDist)
                                siblingDist = temp;
                        } else {
                            // 只是目前这两个element没有共同祖先。兄弟距离视作无穷大。
                            int temp = 100000;
                            if (temp < siblingDist)
                                siblingDist = temp;
                        }
                    }
                    // 判断完q和o的兄弟距离，若其最小兄弟距离<2*cutoff
                    // 为什么是2*cutoff,对于a b c 来说，我们并不知道搜索词中那个是a,哪个是
                    // 所以为了避免这种情况，只好用2*cutoff来当作判断值。
                    if (siblingDist > 2 * this.siblingDistCutoff)
                        return false;
                }
            }
        }
        return true;
    }

    /**
     * 判断该无结构化文档是否是匹配的。
     * 
     * @param content
     * @param query
     * @return
     */
    public static boolean ifMatchInUnstructure(Elements content,
            HashSet<String> query) {
        // get the content from a middle element's parent
        if (content.size() > 50)
            return false;
        int mid = content.size() / 2;
        String text = content.get(mid).parent().parent().parent().text();
        // 获取搜索词q的位置
        HashMap<String, ArrayList<Integer>> queryIndexMap = new HashMap<String, ArrayList<Integer>>();
        for (String q : query) {
            if (!queryIndexMap.containsKey(q)) {
                queryIndexMap.put(q, new ArrayList<Integer>());
            }
            int fromIndex = text.indexOf(q);
            while (fromIndex != -1) {
                queryIndexMap.get(q).add(fromIndex);
                fromIndex = text.indexOf(q, fromIndex + 1);
            }
        }

        // 一般搜索词为2～3个。
        String[] queries = new String[query.size()];
        queries = query.toArray(queries);
        // O(n^2/2)
        for (int m = 0; m < queries.length; m++) {
            String q = queries[m];
            for (int n = m + 1; n < queries.length; n++) {
                String o = queries[n];
                // 找到q和不同于q的下标最短距离
                if (!o.equals(q)) {
                    ArrayList<Integer> qIndex = queryIndexMap.get(q);
                    ArrayList<Integer> oIndex = queryIndexMap.get(o);
                    int dist = 100000;
                    for (int i = 0; i < qIndex.size(); i++) {
                        for (int j = 0; j < oIndex.size(); j++) {
                            int temp;
                            if (qIndex.get(i) > oIndex.get(j)) {
                                // 距离值等于bigIndex-littleIndex-littlIndex's
                                // string's length
                                temp = qIndex.get(i) - oIndex.get(j)
                                        - q.length();
                            } else {
                                temp = oIndex.get(j) - qIndex.get(i)
                                        - o.length();
                            }
                            if (dist > temp)
                                dist = temp;
                        }
                    }
                    // 如果有一个p，o的最近文本距离小于cutoff，则说明逻辑上不是匹配的。
                    if (dist > TextDistCutoff)
                        return false;
                }
            }
        }
        return true;
    }

    private boolean _ifMatchInUnstructure(Elements content,
            HashSet<String> query) {
        // get the content from a middle element's parent
        if (content.size() > 50)
            return false;
        int mid = content.size() / 2;
        String text = content.get(mid).parent().parent().parent().text();
        // 获取搜索词q的位置
        HashMap<String, ArrayList<Integer>> queryIndexMap = new HashMap<String, ArrayList<Integer>>();
        for (String q : query) {
            if (!queryIndexMap.containsKey(q)) {
                queryIndexMap.put(q, new ArrayList<Integer>());
            }
            int fromIndex = text.indexOf(q);
            while (fromIndex != -1) {
                queryIndexMap.get(q).add(fromIndex);
                fromIndex = text.indexOf(q, fromIndex + 1);
            }
        }

        // 一般搜索词为2～3个。
        String[] queries = new String[query.size()];
        queries = query.toArray(queries);
        // O(n^2/2)
        for (int m = 0; m < queries.length; m++) {
            String q = queries[m];
            for (int n = m + 1; n < queries.length; n++) {
                String o = queries[n];
                // 找到q和不同于q的下标最短距离
                if (!o.equals(q)) {
                    ArrayList<Integer> qIndex = queryIndexMap.get(q);
                    ArrayList<Integer> oIndex = queryIndexMap.get(o);
                    int dist = 100000;
                    for (int i = 0; i < qIndex.size(); i++) {
                        for (int j = 0; j < oIndex.size(); j++) {
                            int temp;
                            if (qIndex.get(i) > oIndex.get(j)) {
                                // 距离值等于bigIndex-littleIndex-littlIndex's
                                // string's length
                                temp = qIndex.get(i) - oIndex.get(j)
                                        - q.length();
                            } else {
                                temp = oIndex.get(j) - qIndex.get(i)
                                        - o.length();
                            }
                            if (dist > temp)
                                dist = temp;
                        }
                    }
                    // 如果有一个p，o的最近文本距离小于cutoff，则说明逻辑上不是匹配的。
                    if (dist > this.textDistCutoff)
                        return false;
                }
            }
        }
        return true;
    }

    /**
     * 判断该url是否是匹配的。
     * 
     * @param url
     * @param query
     * @return
     */
    public static boolean judge(String url, HashSet<String> query) {
        try {
            Document doc = Jsoup.connect(url).get();
            // 这个是查看全是自然段情况的。完全是无结构的匹配仲裁
            Elements content = doc.select("b[style]");
            if (isStructurized(content)) {
                // 结构化时的判断过程。
                System.out.println("structurized");
                return ifMatchInStructure(content, query);
            } else {
                // 非结构化时的判断过程。
                System.out.println("unstructurized");
                return ifMatchInUnstructure(content, query);
            }
        } catch (Exception e) {
            System.out.println("error:" + e);
        }
        return false;
    }

    public boolean judgeInstance(String url, HashSet<String> query) {
        try {
            Document doc = Jsoup.connect(url).get();
            // 这个是查看全是自然段情况的。完全是无结构的匹配仲裁
            Elements content = doc.select("b[style]");
            if (_isStructurized(content)) {
                // 结构化时的判断过程。
                System.out.println("structurized");
                return _ifMatchInStructure(content, query);
            } else {
                // 非结构化时的判断过程。
                System.out.println("unstructurized");
                return _ifMatchInUnstructure(content, query);
            }
        } catch (Exception e) {
            System.out.println("error:" + e);
        }
        return false;
    }
}
