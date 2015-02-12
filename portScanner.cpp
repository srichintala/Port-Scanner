#include<iostream>
#include<sstream>
#include<vector>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<string.h>
#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<ifaddrs.h>
#include<linux/if_link.h>
#include<netdb.h>
#include<iomanip>
#include<pthread.h>
#include<map>
#include<string>
#include<poll.h>

#include "ps_parser.cpp"
#define BUF_LEN 4096
#define T_A 1

using namespace std;

struct dns_hdr
{
    unsigned short id; // identification number

    unsigned char rec_des :1; // recursion desired
    unsigned char trunc_msg :1; // truncated message
    unsigned char auth_ans :1; // authoritative answer
    unsigned char purpose_code :4; // purpose of message
    unsigned char query_res :1; // query/response flag

    unsigned char res_code :4; // response code
    unsigned char check_dis :1; // checking disabled
    unsigned char auth_data :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char rec_avail :1; // recursion available

    unsigned short ques_tot; // number of question entries
    unsigned short ans_tot; // number of answer entries
    unsigned short auth_tot; // number of authority entries
    unsigned short res_tot; // number of resource entries
};

struct query
{
    unsigned short qry_type;
    unsigned short qry_class;
};

class combination
{
	public:
		string ip;
		int port;
		string scan;
		int flag;
		string status;
	combination(string i, int p, string s)
	{
		ip = i;
		port = p;
		scan = s;
		flag = 0;
	}
	void setip(string Ip)
	{
		ip = Ip;
	}
	void setport(int p){ port = p;}
	void setscan(string s)
	{
		scan = s;
	}
	void setstatus(string s){ status =s; }
	void printComb(){
	 cout<<endl<<ip;
	 cout<<" ";
	 cout<<port;
	 cout<<" "<<scan;}
};
class port_conclusion
{
    public:
    int port;
    string serv_name;
    vector<string> scan;
    vector<string> status;
    string conclusion;
    port_conclusion()
	{
		port =0;
		serv_name= "";
		conclusion= "";
	}
	void set_serv(string &s)
	{
        serv_name = s;
	}
	void display()
	{
		cout <<left<< setw(10) << port << setw(40) << serv_name;
        for(int i=0;i<scan.size();i++)
        {
            cout<<scan.at(i) << "(" << status.at(i) << ")";
        }
        cout << "\t" << conclusion<< endl;
	}
};
struct pseudo_hdr
{
    u_int32_t s_addr;
    u_int32_t d_addr;
    u_int8_t pc;
    u_int8_t proto;
    u_int16_t tcp_len;
};
vector<combination> task;

vector<string> ips;

int total_tasks = 0;

pthread_mutex_t mutex_c1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_c2 = PTHREAD_MUTEX_INITIALIZER;

int num_tasks = 0;

/* function for calculating checksum*/
unsigned short calculate_checksum(uint16_t *data,int size1)
{
    unsigned long checksum=0;
    uint16_t extra=0;
    int even = size1%2; //check if size of data is odd
    for(int i=size1;i>1;i=i-2)
    {
        checksum = checksum + *data;
        data++;
    }
    if(even!=0)
    {
        *((uint16_t *)&extra) = *(uint16_t *)data;
        checksum += extra;
    }
    unsigned long total;
    uint16_t *partsum = (uint16_t *)&checksum;
    total = partsum[0] + partsum[1]; //divide check sum into two parts (one's complement addition)
    total =  total + (total>>16); //carry
    uint16_t complement;
    complement=(uint16_t)~total; //take complement
    return(complement);
}
void getdnsname(unsigned char *str1,unsigned char *str2)
{
    strcat((char*)str2,".");
    int len = strlen((char*)str2);
    int pt1=0,pt2=0;
    for(int i=0;i<len;i++)
    {
        if(str2[i]=='.')
        {
            str1[pt1] = i-pt2;
            pt1++;
            while(pt2<i)
            {
                str1[pt1]=str2[pt2];
                pt1++;
                pt2++;
            }
            pt2=i+1;
        }
    }
    str1[pt1]='\0';
    pt1++;
}

void detectip(char ip1[])
{

    char ip[NI_MAXHOST], service[NI_MAXSERV];
    struct ifaddrs *addr, *ptr;

    getifaddrs(&addr);
    int i=0;
    for(ptr=addr;ptr!=NULL;i++,ptr=ptr->ifa_next)
    {
        if(ptr->ifa_addr!=NULL)
        {
            if(ptr->ifa_addr->sa_family==AF_INET && strcmp(ptr->ifa_name, "eth0")==0)
            {
                getnameinfo(ptr->ifa_addr, sizeof(struct sockaddr_in),ip, NI_MAXHOST,service,NI_MAXSERV, NI_NUMERICHOST);
                break;
            }
        }
    }
    strcpy(ip1, ip);
    freeifaddrs(addr);

}

void get_conclusion(map<string,string> ss, string &conclusion)
{
        int size = ss.size();
        int syn_filter = 0,udp_filter = 0,nfx_fil=0,ack_fil=0;
        int t[6] = {0,0,0,0,0,0};
        map<string,string>::iterator e;
        if(size == 1)
        {
            e = ss.begin();
            if(e->second.compare("NoResponse")==0)
                conclusion = "Filtered";
            else
                conclusion = e->second;
			return;
        }

        string syn,null,fin,xmas,ack,udp;
        e = ss.find("SYN");
        if(e != ss.end())
        {
            t[0]=1;
            syn = e->second;
        }
        e = ss.find("NULL");
        if(e != ss.end())
        {
            t[1]=1;
            null = e->second;
        }
        e = ss.find("FIN");
        if(e != ss.end())
        {
            t[2]=1;
            fin = e->second;
        }
        e = ss.find("XMAS");
        if(e != ss.end())
        {
            t[3]=1;
            xmas = e->second;
        }
        e = ss.find("ACK");
        if(e != ss.end())
        {
            t[4]=1;
            ack = e->second;
        }
        e = ss.find("UDP");
        if(e != ss.end())
        {
            t[5]=1;
            udp = e->second;
        }
        if(t[0]==1)
        {
            if(syn.compare("Open")==0)
            {
                conclusion = "Open";
                return;
            }
            if(syn.compare("Closed")==0)
            {
                conclusion = "Closed";
                return;
            }
            if(syn.compare("Filtered")==0)
            {
                syn_filter = 1;
            }
        }
        if(t[5]==1)
        {
            if(udp.compare("Open")==0)
            {
                conclusion = "Open";
                return;
            }
            if(udp.compare("Closed")==0)
            {
                conclusion = "Closed";
                return;
            }
            if(udp.compare("Filtered")==0)
            {
                udp_filter =1;
            }
        }
        if(t[1]==1 )
        {
            if(null.compare("Closed")==0)
            {
                conclusion = "Closed";
                return;
            }
            if(null.compare("Filtered")==0)
                nfx_fil = 1;
        }
        if(t[2]==1)
        {
            if(fin.compare("Closed")==0)
            {
                conclusion = "Closed";
                return;
            }
            if(fin.compare("Filtered")==0)
                nfx_fil = 1;
        }
        if(t[3]==1 )
        {
            if(xmas.compare("Closed")==0)
            {
                conclusion = "Closed";
                return;
            }
            if(xmas.compare("Filtered")==0)
                nfx_fil = 1;
        }
        if(t[4]==1)
        {
           if( ack.compare("Unfiltered")==0)
           {
                conclusion = "Unfiltered";
                return;
           }
           if( ack.compare("Filtered")==0)
                ack_fil=1;
        }
        if(t[1] || t[2] || t[3])
        {
            if(syn_filter || nfx_fil || udp_filter || ack_fil)
            {
                conclusion = "Filtered";
                return;
            }
        }
        if(t[0]==1 || t[4]==1)
        {
            conclusion = "Filtered";
            return;
        }
        if(t[1]||t[2]||t[3]||t[5])
        {
            conclusion = "Open | Filtered";
            return;
        }
        else
        {
            conclusion = "Undecidable";
        }
}

void get_service_name(int p,string &name)
{
    short port = htons(p);
    struct servent *ser;
    if((ser = getservbyport(port,"TCP"))==NULL)
    {
        name ="Unassigned";
        return;
    }
    name= ser->s_name;

}

int service_verify(int i,string ip, string &version)
{
        int sock =0;
		sock =socket(AF_INET,SOCK_STREAM,0);
		if(sock<0)
		{
            cout<<"sock error\n";
            return -1;
		}
		struct sockaddr_in src;
		src.sin_family = AF_INET;
		src.sin_port = htons(i);
		char buf[BUF_LEN];
		char sbuf[BUF_LEN];
		char str[15];
		strcpy(str,ip.c_str());
		src.sin_addr.s_addr = inet_addr(str);
		if(connect(sock,(struct sockaddr*)&src, sizeof(src))<0)
		{
            close(sock);
            return -1;
		}

		if(i==43)
		{
            strcpy(sbuf,"Whois www.facebook.com");
            if(send(sock,sbuf,strlen(sbuf),0)<0)
            {
               close(sock);
                return -1;
            }
		}
		if(i==80)
		{
            memset(sbuf,0,sizeof(sbuf)-1);
            strcpy(sbuf,"GET /index.html HTTP1.1\r\n\r\n");
            if(send(sock,sbuf,strlen(sbuf),0)<0)
            {
               close(sock);
                return -1;
            }
		}
		if(recv(sock,buf,BUF_LEN,0)<0)
		{
            close(sock);
            return -1;
		}
		if(i==22)
		{
            string str = buf;
            string str1 = str.substr(0,19);
            version = str1;
		}
		else if(i==24 )
		{
            if(ip.compare("129.79.247.87")==0)
            {

                int j=0;
                if(buf==NULL)
                    {close(sock);
                    return -1;}
                string newbuf = buf;
                size_t s = newbuf.find_first_of(' ');
                s++;
                string str1 = newbuf.substr(s);

                s = str1.find_first_of(' ');
                s++;
                string str2 = str1.substr(s);

                size_t e = str2.find(";");
                e--;
                string str3 = str2.substr(0,e);
                version = str3;

            }
            else
            {
                close(sock);
                return -1;
            }
		}
		else if(i==43)
		{
            istringstream newbuf;
            int f=0;
            if(buf==NULL)
               { close(sock);return -1; }
            newbuf.str(buf);
            for(string line;getline(newbuf,line);)
            {
                if(line.find("Whois Server Version")!=-1)
                {
                    version = line;
                    f=1;
                    break;
                }
            }
            if(f==0)
              { close(sock);return -1; }

        }
		else if(i==80)
		{
            istringstream newbuf;
            int f=0;
            if(buf==NULL)
              { close(sock);return -1; }
            newbuf.str(buf);
            string line;
            for(;getline(newbuf,line);)
            {
                if(line.find("Server:")!=-1)
                {
                    f=1;
                    break;
                }
                line.clear();
            }
            if(f==0)
                { close(sock);return -1; }

            size_t s = line.find_first_of('\r');
            line.at(s) = ' ';
            version = line;

        }
		else if(i==110)
		{
            char *temp;
            if(buf==NULL)
               { close(sock);return -1; }
            temp = strtok(buf,"+OK ");
            if(temp==NULL)
               { close(sock);return -1; }
            temp = strtok(temp," ");
            if(temp==NULL)
               { close(sock);return -1; }
            version = temp;
		}
		else if(i==143)
		{

            if(buf==NULL)
               { close(sock);return -1; }
            string newbuf(buf);
            size_t e = newbuf.find(" ready.");
            if(e==string::npos)
                { close(sock);return -1; }
            size_t s = 0;
            char ch='*';
            for(s=e-1;ch!=' ';s--)
            {

                ch = newbuf.at(s);

            }
            s++;
            string server = newbuf.substr(s+1,e-s);
            size_t m = newbuf.find("IMAP");
            size_t n=0;
            ch='*';
            for(n=m;ch!=' ';n++)
            {
                ch = newbuf.at(n);
            }
            n--;
            string ver = newbuf.substr(m,n-m);

            version = "Version: "+ver+" Server: "+server;
		}
		close(sock);
		return 1;
}

/*dns header fill*/
void dns_fill(int p, string dt, string &status, int query_type)
{
	char dnsbuf[BUF_LEN];
	unsigned char *name;
	unsigned char h_name[15]= "www.google.com";
	unsigned char *host= h_name;

	char *dest = new char[strlen(dt.c_str())+1];
	strcpy(dest,dt.c_str());
	struct sockaddr_in src;

	struct dns_hdr *dns = NULL;
	struct query *q = NULL;

	struct pollfd dnsfds[2];
    dnsfds[0].fd= socket(AF_INET,SOCK_DGRAM, IPPROTO_UDP);
    dnsfds[1].fd= socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(dnsfds[0].fd <0 || dnsfds[1].fd<0)
    {
        cout<<"socket creation error\n";
        status = "Open | Filtered";
        return;
    }

	int timer=4*1000;
    int x=1;
    dnsfds[0].events = POLLIN;
    dnsfds[1].events = POLLIN;

    if(setsockopt(dnsfds[1].fd,IPPROTO_IP,IP_HDRINCL,&x,sizeof(int))<0)
    {
        perror("setsockopt() error");
        exit(-1);
    }

	char myip[NI_MAXHOST];
	int sport= 0;
	while(sport<1025)
	{
		sport=rand()%65535;
	}
	detectip(myip);

	src.sin_family = AF_INET;
	src.sin_port = htons(p);
	src.sin_addr.s_addr = inet_addr(dest);

	dns = (struct dns_hdr *)dnsbuf;

    dns->id = (unsigned short) htons(getpid());
    dns->query_res = 0;
    dns->purpose_code = 0;
    dns->auth_ans = 0;
    dns->trunc_msg = 0;
    dns->rec_des = 1;
    dns->rec_avail = 0;
    dns->z = 0;
    dns->auth_data = 0;
    dns->check_dis = 0;
    dns->res_code = 0;
    dns->ques_tot = htons(1);
    dns->ans_tot = 0;
    dns->auth_tot = 0;
    dns->res_tot = 0;
   

	name =(unsigned char*)(dnsbuf + sizeof(struct dns_hdr));
    
    getdnsname(name , host);
    q =(struct query*)(dnsbuf+ sizeof(struct dns_hdr) + (strlen((const char*)name) + 1));

    q->qry_type = htons(query_type);
    q->qry_class = htons(1);

	socklen_t len = sizeof(src);
    int j=0,dflg=0, iflg=0,some=0;
    time_t n=0,m=0,s=0,e=0;
    char recv_dns[BUF_LEN];
    char recv_icmp[BUF_LEN];
    for(j=0;j<3 && dflg==0 && iflg==0;j++)
    {

		if(sendto(dnsfds[0].fd,dnsbuf,sizeof(struct dns_hdr) + (strlen((const char*)name)+1) + sizeof(struct query),0,(struct sockaddr*)&src,sizeof(src)) < 0)
		{
			continue;
		}

		some = poll(dnsfds,2,timer);
		if(some>0)
		{
			if(dnsfds[0].revents & POLLIN)
			{
				m=time(NULL);
				while(recvfrom (dnsfds[0].fd,recv_dns ,65535, 0 , (struct sockaddr*)&src ,&len ) > 0)
				{
					n=time(NULL);
					if(n-m>=4)
					break;

					status = "Open";
					dflg=1;
					break;
				}
			}
			if(dnsfds[1].revents & POLLIN)
			{
				s=time(NULL);
				while(recvfrom(dnsfds[1].fd, recv_icmp, sizeof(struct dns_hdr) + (strlen((const char*)name)+1) + sizeof(struct query),0, (struct sockaddr *)&src,&len)>0)
				{
					e=time(NULL);
					if((e-s)>=4)
					break;

					struct icmp *icmp1 = (struct icmp *) (recv_icmp + sizeof(struct iphdr));
					if(icmp1->icmp_type==3 && icmp1->icmp_code==3)
                    {
                        status = "Closed";
                        iflg=1;
                        break;
                    }
					if(icmp1->icmp_type == 3 && (icmp1->icmp_code==1 || icmp1->icmp_code==2 || icmp1->icmp_code==9 || icmp1->icmp_code==10 || icmp1->icmp_code==13))
					{
						status = "Filtered";
						iflg=1;
						break;
					}					
				}
			}

		}

	}
	if(dflg==0 && iflg==0)
    {
        status ="Open | Filtered";
    }
	close(dnsfds[0].fd);
	close(dnsfds[1].fd);
}

void scan_udp(int p,string dt, string &status)
{
    char packet[BUF_LEN];
    struct iphdr *ip1 = (struct iphdr *) packet;
    struct udphdr *udp1;
    struct udphdr *udp = (struct udphdr *) (packet + sizeof(struct iphdr));
    memset(packet,0,BUF_LEN);
	char *dest = new char[strlen(dt.c_str())+1];
	strcpy(dest,dt.c_str());
	struct sockaddr_in src;
	struct pollfd fds[2];
    fds[0].fd= socket(AF_INET,SOCK_RAW,IPPROTO_UDP);
    fds[1].fd= socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(fds[0].fd <0 || fds[1].fd<0)
    {
		cout<< "sock() error";
        status = "Open | Filtered";
        return;
    }
    int timer=4*1000;
    int x=1;
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;
    if(setsockopt(fds[0].fd,IPPROTO_IP,IP_HDRINCL,&x,sizeof(int))<0)
    {
        perror("setsockopt() error");
        exit(-1);
    }
    if(setsockopt(fds[1].fd,IPPROTO_IP,IP_HDRINCL,&x,sizeof(int))<0)
    {
        perror("setsockopt() error");
        exit(-1);
    }

    char myip[NI_MAXHOST];
    int sport= 0;
    while(sport<1025)
    {
        sport=rand()%65535;
    }
    detectip(myip);
    src.sin_family = AF_INET;
    src.sin_port = htons(p);
    src.sin_addr.s_addr = inet_addr(dest);

    ip1->ihl = 5;
    ip1->version = 4;
    ip1->tos = 16;
    ip1->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip1->id = htons(54321);
    ip1->frag_off = 0;
    ip1->ttl = 64;
    ip1->protocol = IPPROTO_UDP; // UDP
    ip1->check = 0;
    ip1->saddr = inet_addr(myip);
    ip1->daddr = inet_addr(dest);

    udp->source = htons(sport);
    udp->dest = htons(p);
    udp->len = htons(sizeof(struct udphdr));
    udp->check = 0;
    ip1->check = calculate_checksum((uint16_t *) packet, sizeof(struct iphdr)+(sizeof(struct udphdr)));

    socklen_t len = sizeof(src);
    int j=0,uflg=0, iflg=0,some=0;
    time_t n=0,m=0,s=0,e=0,tot=0,now=0;
    char recv_udp[BUF_LEN];
    char recv_icmp[BUF_LEN];
	tot= time(NULL);
	
    for(j=0;j<3 && uflg==0 && iflg==0 && now-tot<=15;j++)
    {
		now= time(NULL);
        if(sendto (fds[0].fd, packet, sizeof(struct iphdr)+sizeof(struct udphdr) ,  0, (struct sockaddr *) &src, sizeof (src)) < 0)
        {
            cout << "send to failed" << endl;
        }
        some = poll(fds,2,timer);
        if(some>0)
        {
            if(fds[0].revents & POLLIN)
            {
                m=time(NULL);
                while(recvfrom (fds[0].fd,recv_udp ,sizeof(struct iphdr)+sizeof(struct udphdr), 0 , (struct sockaddr*)&src ,&len )>0)
                {
                    n=time(NULL);
                    if(n-m>=4)
                    break;
                    struct iphdr *ip2=(struct iphdr*)(recv_udp);
                    char *saddr=inet_ntoa(*(struct in_addr*)&ip1->daddr);
                    char *daddr=inet_ntoa(*(struct in_addr*)&ip2->saddr);
                    if(strcmp(saddr, dest)==0)
                    {
                        udp1 = (struct udphdr*)(recv_udp + sizeof(struct iphdr));
                        if(udp->dest==udp1->source)
                        {
                            uflg=1;
                            status= "Open";
                            break;
                        }
                    }
                }
            }
            if(fds[1].revents & POLLIN)
            {
                s=time(NULL);
                while(recvfrom(fds[1].fd,recv_icmp,sizeof(struct iphdr)+sizeof(struct icmp),0,(struct sockaddr *)&src,&len)>0)
                {
                    e=time(NULL);
                    if((e-s)>=4)
                    break;

                    struct iphdr *ip2=(struct iphdr*)(recv_icmp);
                    char *saddr=inet_ntoa(*(struct in_addr*)&ip1->daddr);
                    char *daddr=inet_ntoa(*(struct in_addr*)&ip2->saddr);
                    if(strcmp(daddr, dest)==0)
                    {
                        struct icmphdr *icmp1 = (struct icmphdr *) (recv_icmp + sizeof(struct iphdr));
                        udp1 = (struct udphdr *)((char *) icmp1+  sizeof(struct icmphdr) + sizeof(struct iphdr));
						if(icmp1->type == 3 && (icmp1->code==1 || icmp1->code==2 || icmp1->code==9 || icmp1->code==10 || icmp1->code==13))
						{
							status = "Filtered";
							iflg=1;
							break;
						}
						if(icmp1->type==3 && icmp1->code==3)
						{
							status = "Closed";
							iflg=1;
							break;
						}
						break;
                    }
                }
            }
        }
	}
    if(uflg==0 && iflg==0)
    {
        status ="Open | Filtered";
    }
    close(fds[0].fd);
    close(fds[1].fd);

}

int scan(int tcp_flags[], int p, string dt, string &status)
{
	char packet[BUF_LEN], *pseudo;
	struct iphdr *ip1 = (struct iphdr *) packet;
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
	memset(packet,0,BUF_LEN);
	char *dest = new char[strlen(dt.c_str())+1];
	strcpy(dest,dt.c_str());
	struct sockaddr_in src;
	struct pseudo_hdr ph;
	int sockfd = 0;
	int x = 1;

	int icmp_sockfd=0;
	sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

	if(sockfd<0)
	{
	   perror("socket() error");
	   exit(-1);
	}
	char myip[NI_MAXHOST];
	int sport = 0;

	while(sport<1025)
	{
		sport=random()%65535;
	}

    detectip(myip);
	src.sin_family = AF_INET;
	src.sin_port = htons(p);
	src.sin_addr.s_addr = inet_addr(dest);

	ip1->ihl = 5;
	ip1->version = 4;
	ip1->tos = 0;
	ip1->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	ip1->id = htons(54321);
	ip1->frag_off = 0;
	ip1->ttl = 64;
	ip1->protocol = IPPROTO_TCP; // TCP
	ip1->check = 0;
	ip1->saddr = inet_addr(myip);
	ip1->daddr = inet_addr(dest);

	tcp->source = htons(sport);
	tcp->dest = htons(p);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->syn= tcp_flags[0];
	tcp->ack= tcp_flags[1];
	tcp->fin= tcp_flags[2];
	tcp->rst= tcp_flags[3];
	tcp->psh= tcp_flags[4];
	tcp->urg= tcp_flags[5];
	tcp->window = htons(1212);
	tcp->check = 0;
	tcp->urg_ptr = 0;

	ip1->check = calculate_checksum((uint16_t*) packet, sizeof(struct iphdr)+(sizeof(struct tcphdr)));
	
    ph.s_addr = inet_addr(myip);
    ph.d_addr = inet_addr(dest);
    ph.pc = 0;
    ph.proto = IPPROTO_TCP;
    ph.tcp_len = htons(sizeof(struct tcphdr));

    int length = sizeof(struct pseudo_hdr) + sizeof(struct tcphdr);
    pseudo = (char*)malloc(sizeof(char)*length);

    memcpy(pseudo,(char*) &ph , sizeof (struct pseudo_hdr));
    memcpy(pseudo + sizeof(struct pseudo_hdr) , tcp, sizeof(struct tcphdr));

    tcp->check = calculate_checksum((uint16_t *)pseudo,length);
	struct timeval tx;
    tx.tv_sec=4;
    tx.tv_usec=0;

    if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&x,sizeof(int))<0)
    {
        perror("setsockopt() error");
        exit(-1);
    }
	if(setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&tx,sizeof(tx))<0)
    {
        perror("\nrecv timeout error");
        exit(-1);
    }

    socklen_t len = sizeof(src);
    int flag=0;
    struct tcphdr *tcp1;
    char recv_buf[BUF_LEN];
    char icmp_buf[BUF_LEN];
    int j=0, r =0;
	time_t s = 0,e =0;
	int iflg=0;
    for(j=0; j<3 && flag==0;j++)
    {

        if(sendto(sockfd,packet,sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *)&src,sizeof(src))<=0)
        {
           perror("sendto() error");
           exit(-1);
        }

        memset(recv_buf, 0, sizeof(recv_buf)-1);
		s = time(NULL);
        while(recvfrom(sockfd,recv_buf,sizeof(struct iphdr)+sizeof(struct tcphdr),0,(struct sockaddr *)&src,&len)>0)
        {
			e = time(NULL);
			if(e-s>tx.tv_sec)
				break;
            struct iphdr *ip2 = (struct iphdr *)recv_buf;
            char *saddr=inet_ntoa(*(struct in_addr*)&ip1->daddr);
            char *daddr=inet_ntoa(*(struct in_addr*)&ip2->saddr);
            if(strcmp(daddr, saddr)==0)
            {
				tcp1 = (struct tcphdr*)(recv_buf + sizeof(struct iphdr));
				if(tcp->dest==tcp1->source)
				{
                    flag=1;
					break;
                }
            }
        }
    }
    if(j==3 && flag==0)
    {
		icmp_sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(setsockopt(icmp_sockfd,IPPROTO_IP,IP_HDRINCL,&x,sizeof(int))<0)
		{
			perror("setsockopt() error");
			exit(-1);
		}
		if(icmp_sockfd<0)
		{
		   perror("socket() error");
		   exit(-1);
		}
		if(setsockopt(icmp_sockfd,SOL_SOCKET,SO_RCVTIMEO,&tx,sizeof(tx))<0)
		{
			perror("\nrecv timeout error");
			exit(-1);
		}

		if(sendto(icmp_sockfd,packet,sizeof(struct iphdr)+sizeof(tcphdr),0,(struct sockaddr *)&src,sizeof(src))<0)
        {
           perror("sendto() error");
           exit(-1);
        }
        time_t s =0,e=0;
        s= time(NULL);
        while(recvfrom(icmp_sockfd,icmp_buf,sizeof(struct iphdr)+sizeof(struct icmp),0,(struct sockaddr *)&src,&len)>0)
        {
            e=time(NULL);
            if(e-s>=4)
                break;
           
            struct iphdr *ip2 = (struct iphdr *)recv_buf;
            char *saddr=inet_ntoa(*(struct in_addr*)&ip1->daddr);
            char *daddr=inet_ntoa(*(struct in_addr*)&ip2->saddr);
            if(strcmp(daddr, dest)==0)
            {
                struct icmp *icmp1 = (struct icmp *) (icmp_buf + sizeof(struct iphdr));
                tcp1 = (struct tcphdr*)(icmp1 + sizeof(struct iphdr));
				if(tcp->dest==tcp1->dest)
				{
                    if(icmp1->icmp_type == 3 && (icmp1->icmp_code==1 || icmp1->icmp_code==2 || icmp1->icmp_code==3 || icmp1->icmp_code==9 || icmp1->icmp_code==10 || icmp1->icmp_code==13))
                    {
                        iflg=1;
                        status = "Filtered";
                    }
                     break;
                }
            }
        }
        close(icmp_sockfd);
    }

    if(flag == 1)
	{

		if(tcp->syn==1)
		{
			if(tcp1->syn == 1 )
			{
				if(tcp1->ack == 0 || tcp1->ack==1 )
				{
					status = "Open";									
					delete dest;
					close(sockfd);
					return 1;
				}
			}
		}
		if(tcp1->rst == 1)
		{
            status = "Closed";

		}
    }
    if(iflg == 0 && tcp->syn == 1 && flag==0)
    {
        status = "NoResponse";

    }
    else if(tcp->ack == 1)
    {
        if(flag==1 && tcp1->rst == 1)
        {
            status = "Unfiltered";

        }
        else if(flag==0 && iflg == 0)
        {
            status =  "NoResponse";

        }
    }
    else if(tcp->fin ==1 || tcp->psh ==1 || tcp->urg == 1)
    {

        if(flag==0 && iflg==0)
        {
            status = "Open | Filtered";

        }
        if(flag == 1 && tcp1->rst ==1)
        {
            status = "Closed";

        }
		else if(flag==1 && tcp1->ack == 1)
		{
			status = "Closed";
		}
    }
    else
    {
        if(flag ==0 && iflg ==0)
        {
            status = "Open | Filtered";
        }
        if(flag == 1 && tcp1->rst ==1)
        {
            status = "Closed";
        }
		else if(flag==1 && tcp1->ack == 1)
		{
			status = "Closed";
		}
    }

    delete dest;
    close(sockfd);
    return 0;
}

void * scan_func(void *)
{
	int index = 0;

    for(int i=0;i<total_tasks;i++)
    {
		pthread_mutex_lock(&mutex_c1);
		if(num_tasks<total_tasks)
		{
			index = num_tasks;
			num_tasks++;
		}
		else
		{
			pthread_mutex_unlock(&mutex_c1);
			break;
		}
		pthread_mutex_unlock(&mutex_c1);
        if(task.at(index).scan.compare("UDP")==0)
        {
			if(task.at(index).port==53)
			{
				dns_fill(task.at(index).port, task.at(index).ip,task.at(index).status, T_A);
			}
			else
			{
				scan_udp(task.at(index).port,task.at(index).ip,task.at(index).status);

			}
			continue;
        }
		int t[6]={0,0,0,0,0,0}; //syn ack fin rst psh urg 
		if(task.at(index).scan.compare("SYN")==0)
		{
			t[0] = 1;
		}
		else if(task.at(index).scan.compare("FIN")==0)
		{
			t[2] = 1;
		}
		else if(task.at(index).scan.compare("XMAS")==0)
		{
			t[2] = 1;
			t[4] = 1;
			t[5] = 1;
		}
		else if(task.at(index).scan.compare("ACK")==0)
		{
			t[1] = 1;
		}
		scan(t,task.at(index).port,task.at(index).ip,task.at(index).status);
	}
}

int main(int argc, char *argv[])
{
	time_t st;
	st = time(NULL);
	pthread_t t_id[5];
	ps_args_s ps_args;
	parse_args(&ps_args, argc, argv);

	if(ps_args.ip==1)
		ips.push_back(ps_args.ip_addr);

	if(ps_args.f==1)
	{
		for(int i=0;i<ps_args.file_ips.size();i++)
        {
            ips.push_back(ps_args.file_ips.at(i));
        }
	}
	if(ps_args.prefix!=-1)
	{
		for(int i=0;i<ps_args.p_ips.size();i++)
			ips.push_back(ps_args.p_ips.at(i));

	}
	total_tasks = ips.size() * ps_args.num_ports * ps_args.scan_flags.size();
	for(int i=0;i<ips.size();i++)
	{
		for(int j=0;j<ps_args.num_ports;j++)
		{
			for(int k=0;k<ps_args.scan_flags.size();k++)
			{
				combination c(ips.at(i),ps_args.ports[j],ps_args.scan_flags.at(k));
				task.push_back(c);
			}
		}
	}
	
	cout<< "Scanning..."<<endl<<endl;
	for(int i=0;i<ps_args.speedup;i++)
	{
		pthread_create( &t_id[i], NULL, scan_func, NULL );
	}
	for(int i=0;i<ps_args.speedup;i++)
		pthread_join( t_id[i], NULL);
	
	time_t en;
	en = time(NULL);
	
	cout<< "Scan took "<<en-st<<" seconds."<<endl;
    map<string, string> ss;
	vector<port_conclusion> pc;
	int t=0;
	string con;
	for(int i=0;i<ips.size();i++)
	{
        cout << endl << endl << "IP address: " <<ips.at(i);
        cout << endl << "Open Ports:" << endl;
        cout << left << setw(10) << "Port" << setw(40) << "Service Name (if applicable)" << setw(80) << "Results" << setw(15)<<"Conclusion" << endl;
        cout << "-----------------------------------------------------------------------------------------------------------------------------------------------" << endl;
		for(int j=0;j<ps_args.num_ports;j++)
		{
            port_conclusion temp_port;
            string serv;
            string temp_serv;
            temp_port.port = task.at(t).port;
			for(int k=0;k<ps_args.scan_flags.size();k++)
			{
				ss.insert(pair<string , string>(task.at(t).scan,task.at(t).status));
				temp_port.scan.push_back(task.at(t).scan);
				if(task.at(t).status.compare("NoResponse")==0)
				temp_port.status.push_back("Filtered");
				else
				temp_port.status.push_back(task.at(t).status);
				t++;
			}
			if(temp_port.port<=1024)
			get_service_name(temp_port.port,serv);
            get_conclusion(ss,temp_port.conclusion);
			ss.clear();
			if(temp_port.conclusion.compare("Open")==0)
			{
                if(temp_port.port == 22 || temp_port.port == 24 || temp_port.port == 43 ||temp_port.port == 80 || temp_port.port == 110 || temp_port.port == 143)
                {
                    int chk =0;
                    chk=service_verify(temp_port.port,task.at(t-1).ip,temp_serv);
                    if(chk==-1)
                        temp_port.set_serv(serv);
                    else
                        temp_port.set_serv(temp_serv);
                }
                temp_port.display();
			}
			else
            {
                temp_port.serv_name = serv;
                pc.push_back(temp_port);
            }

		}
		if(pc.size()==0)
            continue;
		cout << '\n' << "Closed/Filtered/Unfiltered Ports:" << endl;
        cout << left << setw(10) << "Port" << setw(40) << "Service Name (if applicable)" << setw(80) << "Results" <<setw(15) << "Conclusion" << endl;
        cout << "----------------------------------------------------------------------------------------------------------------------------------------" << endl<<endl;
        for(int ps=0;ps<pc.size();ps++)
        {
            pc.at(ps).display();
        }
		pc.clear();
	}
}
