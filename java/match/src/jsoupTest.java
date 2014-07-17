import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Vector;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class jsoupTest {
    // 判断文档是否是结构化的
    public static final int TextLengthCutoff = 300;
    // 判断兄弟节点距离的cutoff
    public static final int SiblingDistCutoff = 15;
    // 判断文本距离的cutoff
    public static final int TextDistCutoff = 10;

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

    public static void main(String[] args) {
        String url = "http://cache.baiducontent.com/c?m=9d78d513d9d430ad4f9ae3690c66c0166f43f3622ba7da020bd58448e2732d465017e4ac57530772d3d20c1316d93a4beb802103441456b58cc9f85dacb085595e9f5134676c815613a30ed9cb5151cb37e658fed91bf0ba8125e5a9c5a2d84323bb44737a9780ff4d7667de28b04a3eb9e0df0a025e63a7f06136a4012c75ca3440c10da4bd6f3e1081818c0113de7b88295b8aaf37b23411b60ea5181e2740aa5bb17f0b606f&p=c63dc64ad49f1ddd1ebd9b7d0b16c1&newp=8b2a975e86cc42a958bac337465ebb231610db2151d4da1564&user=baidu&fm=sc&query=%C0%EE%BD%A3%B8%F3+%D5%C5%BC%D2%BF%DA%CA%D0%C9%CC%D2%B5%D2%F8%D0%D0+%D5%C5%BC%D2%BF%DA&qid=&p1=73";
        HashSet<String> query = new HashSet<String>();
        query.add("李剑阁");
        query.add("张家口市商业银行");
        System.out.println(judge(url, query));
    }

    static void testCase() {
        Document doc = null;
        try {
            doc = Jsoup.connect(
                    "http://www.menneske.no/arukone/5x5/eng/?number=499").get();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Elements contents = doc.getElementsByClass("arukone");
        Elements datas = contents.get(0).getElementsByTag("table");
        for (Element data : datas) {

            Elements trs = data.getElementsByTag("tr");
            for (int i = 0; i < trs.size(); i++) {
                Elements tds = trs.get(i).getElementsByTag("td");
                for (int j = 0; j < tds.size(); j++) {
                    System.out.println("index:"
                            + tds.get(j).elementSiblingIndex());

                }

                for (int j1 = 0; j1 < tds.size(); j1++) {
                    if (!"".equals(tds.get(j1).text())) {
                        System.out.println(tds.get(j1).text() + "," + i + ","
                                + j1);
                    }
                }
            }
        }

    }

    static void findCutoff(String url) {
        try {
            Document doc = Jsoup.connect(url).get();
            Vector<HashMap<String, Integer>> map = new Vector<HashMap<String, Integer>>();
            Map<String, Integer> tagCount = new HashMap<String, Integer>();
            Map<Integer, Integer> lenCount = new HashMap<Integer, Integer>();
            // 这个是查看全是自然段情况的。完全是无结构的匹配仲裁
            Elements content = doc.getAllElements();
            int max = 0;
            String tag = null;
            for (Element e : content) {// 此处就是遍历了

                if (e.ownText().length() > 0) {
                    String key = e.nodeName();
                    int len = e.ownText().length();
                    HashMap<String, Integer> ins = new HashMap<>();
                    ins.put(key, len);
                    map.add(ins);
                    if (len > max) {
                        max = len;
                        tag = key;
                    }
                    if (lenCount.containsKey(len)) {
                        lenCount.put(len, lenCount.get(len) + 1);
                    } else {
                        lenCount.put(len, 1);
                    }
                    if (tagCount.containsKey(key)) {
                        tagCount.put(key, tagCount.get(key) + 1);
                    } else {
                        tagCount.put(key, 1);
                    }
                }
            }
            System.out.println(map);
            System.out.println(tagCount);
            System.out.println(lenCount);
            System.out.println(tag + ":" + max);

        } catch (IOException e) {
            // TODO Auto-generated catch block
            // e.printStackTrace();
        }
    }
}
