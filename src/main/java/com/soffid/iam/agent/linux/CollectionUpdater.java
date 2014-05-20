package com.soffid.iam.agent.linux;

public interface CollectionUpdater<F, S> {
	boolean areEqual (F first, S second);
	void onSecond (S obj) throws Exception;
	void onFirst (F obj) throws Exception;
	void onBoth (F first, S second) throws Exception;
}
