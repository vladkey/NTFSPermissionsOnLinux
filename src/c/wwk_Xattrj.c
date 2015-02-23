
#include <stdlib.h>
#include <string.h>
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
    // That's embarassing: `getfattr -n some_ntfs_file` does not dump anything. a bug somewhere?
    jobjectArray stringArray = NULL;
	const char *filePath= (*env)->GetStringUTFChars(env, jfilePath, NULL);

	int bufferLength = listxattr(filePath, NULL, 1024);
//	printf("bufferLength(%s) = %d\n", filePath, bufferLength);
	if(bufferLength <= 0) {
    	char *buffer = (char*) malloc(bufferLength);
    	int s = listxattr(filePath, buffer, bufferLength);
        if (s >= 0) {
        	int count = 0;
        	char *p = buffer;
        	while (p < buffer + bufferLength) {
        	    // FIXME check if correct for non-European UTF8
                // strlen() will truncate if UTF8 string contains \0 byte in multi-byte char representation
        	    p += (strlen(p) + 1);
        	    count++;
        	}
//        	printf("count = %d\n", count);

        	jclass stringClass = (*env)->FindClass(env, "java/lang/String");
        	stringArray = (*env)->NewObjectArray(env, count, stringClass, 0);
        
    		p = buffer;
    		for (int i = 0; i < count;i++) {
//                printf("attrib[%d] = %s\n", i, p);
				jstring javaString = (*env)->NewStringUTF(env, p);
				(*env)->SetObjectArrayElement(env, stringArray, i, javaString);
				p += (strlen(p) + 1);
    		}
	    }
        free(buffer);
	}

	(*env)->ReleaseStringUTFChars(env, jfilePath, filePath);

	return stringArray;
}

/*
 * Class:     wwk_Xattrj
 * Method:    writeAttribute
 * Signature: (Ljava/lang/String;Ljava/lang/String;[B)Z
 */
JNIEXPORT jboolean JNICALL Java_wwk_Xattrj_writeAttribute(JNIEnv * env, jobject xattrj, jstring jfilePath, jstring jattrName, jbyteArray jbytes)
{
    const char *filePath = (*env)->GetStringUTFChars(env, jfilePath, 0);
    const char *attrName = (*env)->GetStringUTFChars(env, jattrName, 0);

    jbyte *attrValue = (*env)->GetByteArrayElements(env, jbytes, NULL);
    size_t nBytes = (*env)->GetArrayLength(env, jbytes);

    int res = setxattr(filePath, attrName, (void *)attrValue, nBytes, 0);

    (*env)->ReleaseByteArrayElements(env, jbytes, attrValue, 0);

    (*env)->ReleaseStringUTFChars(env, jattrName, attrName);
    (*env)->ReleaseStringUTFChars(env, jfilePath, filePath);

    return (res == 0) ? JNI_TRUE : JNI_FALSE;
}
