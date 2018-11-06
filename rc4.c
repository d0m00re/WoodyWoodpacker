
static inline void swap(unsigned char *p1, unsigned char *p2)
{
	unsigned char t = *p1;
	*p1 = *p2;
	*p2 = t;
}

void rc4(unsigned char *key,int key_len,char *buff,int len)
{
	unsigned char	s[256];
	unsigned char	t[256];
	int		i,j=0;
	char            *k=key;

	for (i = 0; i < 256; i++){
		s[i] = i;
		t[i] = k[i % key_len];
	}
	for (i = 0; i < 256; i++){
		j = (j + s[i] + t[i]) % 256;
		swap(&s[i],&s[j]);
	}
	unsigned long t1,t2;
	unsigned char val;
	unsigned char out; 
	t1=0;
        t2=0;
	for (i = 0; i < len; i++){     
		t1 = (t1 + 1) % 256;
		t2 = (t2 + s[t1]) % 256;
		swap(&s[t1], &s[t2]);
		val = (s[t1] + s[t2]) % 256;
		out = *buff ^ val;
		*buff=out;
		buff++;
	} 
}
/*
int main()
{
	unsigned char key[] = {0x41, 0x42, 0x43, 0x44};
	char msg[100];
	strcpy(msg, "hello there i am ryota.");
	rc4(key, sizeof(key), msg, sizeof(msg));
	rc4(key, sizeof(key), msg, sizeof(msg));
	printf("msg recoverred?:%s\n", msg);
	return (0);
	
}
*/
