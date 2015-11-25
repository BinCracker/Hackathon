def invert(e,N):
        (x1,x2,x3)=(1,0,e)
        (y1,y2,y3)=(0,1,N)
        while y3:
                q=x3/y3
                (t1,t2,t3)=(x1-q*y1,x2-q*y2,x3-q*y3)
                (x1,x2,x3)=(y1,y2,y3)
                (y1,y2,y3)=(t1,t2,t3)
        if x1<0:
                x1=x1+N
        return x1#,x2,x3

#return d
