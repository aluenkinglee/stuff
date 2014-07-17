这里提到的伪匹配的概念是指在网上搜索某些特征词，比如人名公司手机QQ号等内容时，网页反馈的结果：重要关键词在人看来是逻辑没有关联的时候就是伪匹配。

比如说，某XX，公司名，地点很明显的构成一个记录的时候，在人看来是个写在一起的，那么结果就是匹配的。相反，要是搜索词相距很远，那么就是伪匹配。

那么好，人工审核此类内容是否匹配时，是个无聊枯燥的工作内容，那么只好找机器帮忙，思路也很简单，分析样本伪匹配的原因是什么？和网页文档有什么不同？

对目标网页的分析可以发现，搜索词在目标网页中有时是结构化存在的，就是搜索词处在不同的节点中，节点关系为树中的关系，或者是兄弟关系，或者是父子关系。
同时还有非结构化的内容，比如搜索词是在同一个节点中，此时就不存在上述判断关系，只能由另外一种关系来处理。
<!-- more -->
接着说，当是结构化的关系的时候，从我们人的观点来看，他们应该是兄弟节点，相邻很近，或者用另外一个距离：节点到最近祖先再到另外一个节点的距离。此距离也是很近的。

当时非结构话的关系时，他们是在用一语意范围内，所以字符距离很近。

OK，有了上面的思路，我们所做的就是分析统计目标网页的结构，然后查看具体指标的范围。

首先看如何区分是否结构化，这个可以依靠text的长度来判断（这是分析后发现的）。

```octave
x1=[54,161,70,65,66,3369,101,50,167];
y1=[1,1,1,1,1,1,1,1,1];
x2=[114265,89406,137824,11300,14001,54575,108596,78197,67810,11948,8660,2677,103724,8686];
y2=[0 0 0 0 0 0 0 0 0 0 0 0 0 0];
figure ;
plot(x1,y1,'rx','MarkerSize',10);
hold on;
plot(x2,y2,'bo','MarkerSize',10);
```

数据是分析后得到的。

分布图如下：

![是否结构化与最长文本长度分布图](https://raw.githubusercontent.com/aluenkinglee/aluenkinglee.github.io/source/source/images/2014-07-09-wei-pi-pei/false%20match1.png "是否结构化与最长文本长度分布图")

从图形分界出来看，max(x1)=3369,min(x2)=2677,这个cutoff可以选取2677～3369之间的长度即可。

代码如下,摘选了函数的一部分，url是函数的形参。

```java
        try {
            Document doc = Jsoup.connect(url).get();
            Vector<HashMap<String, Integer>> map = new Vector<HashMap<String, Integer>>();
            Map<String, Integer> tagCount = new HashMap<String, Integer>();
            Map<Integer, Integer> lenCount = new HashMap<Integer, Integer>();
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
```

接着在做搜索节点的距离值的分布，一个搜索词可以会出现在不同的位置，既然搜索词之间有关联效应，那么，即使出现位置很多，
也会有不同的搜索词因为语意关联的缘故，他们的节点距离是很近的，照这个思路，有了以下的分布图。

网页结构化中伪匹配,节点距离兄弟距离的分布图图示如下：

![网页结构化中伪匹配节点距离兄弟距离的分布图](https://raw.githubusercontent.com/aluenkinglee/aluenkinglee.github.io/source/source/images/2014-07-09-wei-pi-pei/false%20match3.png "网页结构化中伪匹配节点距离兄弟距离的分布图")

这个尾部节点兄弟距离太大了，一定是伪匹配的的，看数据较小的距离分布。

![网页结构化中伪匹配节点距离兄弟距离的分布图](https://raw.githubusercontent.com/aluenkinglee/aluenkinglee.github.io/source/source/images/2014-07-09-wei-pi-pei/false%20match4.png "网页结构化中伪匹配节点距离兄弟距离的分布图")

从图可以看出，节点距离和伪匹配的关系不大，主要是兄弟距离起作用。

而兄弟距离于未匹配的分布图：

![兄弟距离于未匹配的分布图](https://raw.githubusercontent.com/aluenkinglee/aluenkinglee.github.io/source/source/images/2014-07-09-wei-pi-pei/false%20match5.png "兄弟距离于未匹配的分布图")

各个距离的直方图如下：

![兄弟距离于未匹配的直方图](https://raw.githubusercontent.com/aluenkinglee/aluenkinglee.github.io/source/source/images/2014-07-09-wei-pi-pei/false%20match6.png "兄弟距离于未匹配的直方图")

其中X轴是兄弟距离长度，y是个数。范围值可以选在3-28之间。

而在无结构中，搜索词的语意判断就是文本距离，搜索词的下标靠的很近。图示如下：

![间隔分布图](https://raw.githubusercontent.com/aluenkinglee/aluenkinglee.github.io/source/source/images/2014-07-09-wei-pi-pei/false%20match2.png "间隔分布图")

文本长度的数据（取一个网页中搜索词之间距离的最小值）为`4 13 25 58 89 102 249 893 1356 2000 2445 3023 4243 12533 13234`
,从这个可以看出，距离很大的肯定就是伪匹配了，最小值的这个不确定。

完整代码请看[这里](https://github.com/aluenkinglee/stuff/tree/master/java/match) 
