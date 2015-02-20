
#include <stdlib.h>
#include <jni.h>
#include "wwk_Xattrj.h"
#include <sys/xattr.h>

/*
 * Class:     wwk_Xattrj
 * Method:    readAttribute
 * Signature: (Ljava/lang/String;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_wwk_Xattrj_readAttribute(JNIEnv * env, jobject xattrj, jstring jfilePath, jstring jattrName)
{
	jbyteArray jvalue = NULL;

	const char *filePath = (*env)->GetStringUTFChars(env, jfilePath, NULL);
	const char *attrName = (*env)->GetStringUTFChars(env, jattrName, NULL);

	int bufferLength = getxattr(filePath, attrName, NULL, 0);
	if (bufferLength > 0) {
		jbyte *buffer = (jbyte*) malloc(bufferLength);
		int len = getxattr(filePath, attrName, buffer, bufferLength);
		if (len > 0) {
			jvalue = (*env)->NewByteArray(env, bufferLength);
			(*env)->SetByteArrayRegion(env, jvalue, 0, bufferLength, buffer);
		}
		free(buffer);
	}

	(*env)->ReleaseStringUTFChars(env, jfilePath, filePath);
	(*env)->ReleaseStringUTFChars(env, jattrName, attrName);

	return jvalue;
}

/*
 * Class:     wwk_Xattrj
 * Method:    listAttributes
 * Signature: (Ljava/lang/String;)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_wwk_Xattrj_listAttributes(JNIEnv * env, jobject xattrj, jstring jfilePath)
{
	const char *filePath= (*env)->GetStringUTFChars(env, jfilePath, NULL);
	int bufferLength = listxattr(filePath, NULL, 0);
	if(bufferLength <= 0)
		return NULL;

	char *buffer = (char*) malloc(bufferLength);
	int s = listxattr(filePath, buffer, bufferLength);
	jclass stringClass = (*env)->FindClass(env, "java/lang/String");
	jobjectArray stringArray = NULL;
/*
	if (s >= 0) {
		stringArray = NewObjectArray(env, s, stringClass, 0 );

		char* p = buffer;
		char* lp = p;
		for (int i = 0; i < s; i++) {
			if(*p == 0) {
				attributeNames[attrCount++] = (p-lp);
				lp = p+sizeof(char);
			}
			p++;
		}
	}

		char* bp = buffer;
		for(int i=0; i<attributeNames.size();i++){
					jstring javaString = memJstr(env, bp, attributeNames[i]);
					(*env)->SetObjectArrayElement(stringArray, i, javaString);

					// we have to increase the string start pntr
					bp = bp + attributeNames[i]+sizeof(char); // +1 skip Null byte
		}
*/
	(*env)->ReleaseStringUTFChars(env, jfilePath, filePath);
	free(buffer);

	return stringArray;
}

/*
 * Class:     wwk_Xattrj
 * Method:    writeAttribute
 * Signature: (Ljava/lang/String;Ljava/lang/String;[B)Z
 */
JNIEXPORT jboolean JNICALL Java_wwk_Xattrj_writeAttribute(JNIEnv * env, jobject xattrj, jstring jfilePath, jstring jattrName, jbyteArray jbytes)
{
	int res = -1;
        return (res == 0) ? JNI_TRUE : JNI_FALSE;
}


