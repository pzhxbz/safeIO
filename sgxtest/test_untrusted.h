#pragma once
extern "C"
{
	int unsafe_initSocket(int *socket, char* ip, int port);
	int unsafe_send(int s, const char *buf, int len, int flags);
	int unsafe_recv(int s, char* buf, int len, int flags);
	int unsafe_closesocket(int s);
}
extern "C"
{
	int unsafe_sendto(int s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
	int unsafe_recvfrom(int s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);

}