package com.soffid.iam.agent.linux;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

public class CollectionComparator<F,S> {
	CollectionUpdater<F, S> updater;
	public CollectionComparator(CollectionUpdater<F,S> updater)
	{
		this.updater = updater;
	}
	
	void compare (Collection<F> firstColl, Collection<S> secondColl) throws Exception
	{
		LinkedList<S> secondList = new LinkedList<S>(secondColl);
		for (F first: firstColl)
		{
			boolean found = false;
			for (Iterator<S> it = secondList.iterator(); 
					it.hasNext(); )
			{
				S second = it.next();
				if (updater.areEqual(first, second))
				{
					updater.onBoth(first, second);
					it.remove();
					found = true;
					break;
				}
			}
			if (! found)
			{
				updater.onFirst(first);
			}
		}
		for (S second: secondList)
		{
			updater.onSecond(second);
		}
	}
}
